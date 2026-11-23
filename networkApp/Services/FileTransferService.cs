using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    public enum TransferDirection { Send, Receive }

    public enum TransferState
    {
        Offering,          // gửi: chờ bên kia đồng ý
        AwaitingDecision,  // nhận: chờ người dùng bấm Nhận / Từ chối
        Preparing,         // nhận: đang băm lại phần .part có sẵn trước khi resume
        Transferring,
        Reconnecting,      // gửi: mất kết nối → đang tự kết nối lại để resume
        Paused,            // nhận: mất kết nối → giữ .part, chờ bên gửi quay lại
        Verifying,         // đang đối chiếu SHA-256
        Completed,
        Rejected,
        Canceled,
        Failed,
    }

    public enum TransferError { None, Timeout, Rejected, Integrity, DiskFull, Io, PeerGone, Busy }

    /// <summary>Ảnh chụp bất biến trạng thái một transfer — an toàn để chuyển sang UI thread.</summary>
    public sealed record TransferSnapshot(
        Guid Id, string PeerFingerprint, TransferDirection Direction, string FileName, long Size,
        long Done, double BytesPerSecond, TransferState State, TransferError Error, string? Detail,
        string? LocalPath, long ResumedFrom, int Reconnects);

    /// <summary>
    /// Truyền file CONSENT-FIRST + RESUME TỰ ĐỘNG + KIỂM TOÀN VẸN ĐẦU-CUỐI:
    ///
    ///   Sender                                   Receiver
    ///   ── FileOffer {id, tên, size, key} ──▶     (thẻ "Nhận / Từ chối" trong khung chat)
    ///   ◀─ FileAccept {id, offset} ─────────      offset = độ dài .part có sẵn → RESUME
    ///   ── FileChunk {id, offset, data} × N ─▶    chỉ ghi khi offset == số byte đã có
    ///   ── FileComplete {id, SHA-256} ──────▶     đối chiếu SHA-256 toàn file
    ///   ◀─ FileResult {id, OK | sai hash} ──      .part → đổi tên thành file thật
    ///
    /// • .part gắn với NỘI DUNG (người gửi + tên + kích thước + thời điểm sửa) chứ không chỉ tên:
    ///   gửi một file KHÁC cùng tên sẽ không bị nối nhầm vào phần dở của file cũ.
    /// • Chunk mang offset tuyệt đối → ghi idempotent: chunk trùng bị bỏ, chunk vượt (mất gói
    ///   khi đổi kết nối) → bên nhận gửi lại FileAccept như một "yêu cầu tua" (giống ACK tích lũy).
    /// • Mất mạng giữa chừng → bên gửi tự kết nối lại (backoff) tới BẤT KỲ địa chỉ mới nào của
    ///   peer, gửi lại offer cùng id; bên nhận nhận ra transfer đã được đồng ý → tự resume,
    ///   không hỏi lại người dùng. Trong suốt với người dùng: chỉ thấy "Đang kết nối lại…".
    /// • SHA-256 toàn file được tính dần trong lúc truyền (không đọc file thêm lần nào).
    /// </summary>
    public sealed class FileTransferService : IDisposable
    {
        public const int ChunkSize = 128 * 1024;
        private const int ChunkHeader = 16 + 8;
        private static readonly TimeSpan OfferTimeout = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan ResumeAcceptTimeout = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan ResultTimeout = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan ReconnectWindow = TimeSpan.FromMinutes(3);
        private const int ProgressIntervalMs = 150;

        private enum RejectReason : byte { User = 0, DiskFull = 1, Busy = 2, Invalid = 3 }
        private enum ResultStatus : byte { Ok = 0, HashMismatch = 1, IoError = 2 }

        private sealed record OfferMsg(Guid Id, string Name, long Size, string ContentKey, bool Resume);
        private sealed record AcceptMsg(Guid Id, long Offset);

        private readonly MessagingService _msg;
        public string SaveFolder { get; }

        private readonly ConcurrentDictionary<Guid, Outgoing> _out = new();
        private readonly ConcurrentDictionary<Guid, Incoming> _in = new();
        private readonly ConcurrentDictionary<Guid, string> _completedIncoming = new(); // id → fp
        private readonly CancellationTokenSource _cts = new();

        public event Action<TransferSnapshot>? Updated;

        // ------------------------------------------------------------------
        private abstract class TransferBase
        {
            public required Guid Id { get; init; }
            public required string PeerFp { get; init; }
            public required string FileName { get; init; }
            public required long Size { get; init; }
            public TransferState State;
            public TransferError Error;
            public string? Detail;
            public string? LocalPath;
            public long Done;
            public long ResumedFrom = -1;
            public int Reconnects;

            // đo tốc độ (EWMA)
            public long LastReportTick;
            public long LastReportBytes;
            public double Speed;
        }

        private sealed class Outgoing : TransferBase
        {
            public required string Path { get; init; }
            public required string ContentKey { get; init; }
            public readonly CancellationTokenSource Cts = new();
            public volatile TaskCompletionSource<long>? AcceptTcs;
            public volatile TaskCompletionSource<ResultStatus>? ResultTcs;
            public long SeekRequest = -1;
            public bool EverAccepted;
            public bool CanceledByPeer;
            public IncrementalHash Hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            public long HashedUpTo;
        }

        private sealed class Incoming : TransferBase
        {
            public required OfferMsg Offer { get; init; }
            public required string PartPath { get; init; }
            public readonly SemaphoreSlim Lock = new(1, 1);
            public FileStream? Stream;
            public IncrementalHash? Hash;
            public bool Consented;
            public long LastResyncAt = -1;
        }

        public FileTransferService(MessagingService msg, string saveFolder)
        {
            _msg = msg;
            SaveFolder = saveFolder;
            Directory.CreateDirectory(SaveFolder);
            _msg.FrameHandler = HandleFrameAsync;
            _msg.SessionLost += OnSessionLost;
            _ = Task.Run(CleanupStalePartFiles);
        }

        // ==================================================================
        //  BÊN GỬI
        // ==================================================================

        public Guid StartSend(string peerFp, string filePath)
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists) throw new FileNotFoundException(filePath);

            // contentKey: dấu vân tay "phiên bản file" — đổi nội dung (mtime/size) là đổi key
            string contentKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{fi.Name}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}")), 0, 12);

            var t = new Outgoing
            {
                Id = Guid.NewGuid(), PeerFp = peerFp, FileName = fi.Name, Size = fi.Length,
                Path = fi.FullName, ContentKey = contentKey, State = TransferState.Offering,
            };
            _out[t.Id] = t;
            Report(t, force: true);
            _ = Task.Run(() => RunSendAsync(t));
            return t.Id;
        }

        private async Task RunSendAsync(Outgoing t)
        {
            CancellationToken ct = t.Cts.Token;
            DateTime lastAlive = DateTime.UtcNow;
            try
            {
                for (int attempt = 0; ; attempt++)
                {
                    try
                    {
                        await SendOnceAsync(t, resume: t.EverAccepted, ct).ConfigureAwait(false);
                        return;
                    }
                    catch (Exception ex) when (IsTransient(ex) && t.EverAccepted && !ct.IsCancellationRequested)
                    {
                        // Mạng rớt giữa chừng → kết nối lại và resume, KHÔNG làm phiền người dùng
                        if (t.Done > 0 && t.State == TransferState.Transferring) lastAlive = DateTime.UtcNow;
                        if (DateTime.UtcNow - lastAlive > ReconnectWindow)
                            throw new TransferException(TransferError.PeerGone, ex.Message);

                        t.State = TransferState.Reconnecting;
                        t.Reconnects++;
                        t.Detail = ex.Message;
                        t.Speed = 0;
                        Report(t, force: true);
                        int delay = Math.Min(1000 * (1 << Math.Min(attempt, 3)), 8000); // 1,2,4,8,8...s
                        await Task.Delay(delay, ct).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                if (!t.CanceledByPeer) _ = SendSafe(t.PeerFp, PacketType.FileCancel, t.Id.ToByteArray());
                t.State = TransferState.Canceled;
                t.Detail = t.CanceledByPeer ? "peer" : null;
            }
            catch (TransferException tex)
            {
                if (tex.Error == TransferError.Timeout)
                    _ = SendSafe(t.PeerFp, PacketType.FileCancel, t.Id.ToByteArray()); // rút lại lời mời
                t.State = tex.Error == TransferError.Rejected ? TransferState.Rejected : TransferState.Failed;
                t.Error = tex.Error;
                t.Detail = tex.Message;
            }
            catch (Exception ex)
            {
                t.State = TransferState.Failed;
                t.Error = IsTransient(ex) ? TransferError.PeerGone : TransferError.Io;
                t.Detail = ex.Message;
            }
            finally
            {
                t.Speed = 0;
                Report(t, force: true);
                _out.TryRemove(t.Id, out _);
                t.Hash.Dispose();
                t.Cts.Dispose();
            }
        }

        private async Task SendOnceAsync(Outgoing t, bool resume, CancellationToken ct)
        {
            // ---- 1. Offer & chờ đồng ý ----
            var acceptTcs = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
            t.AcceptTcs = acceptTcs;
            Interlocked.Exchange(ref t.SeekRequest, -1);

            var offer = new OfferMsg(t.Id, t.FileName, t.Size, t.ContentKey, resume);
            await _msg.SendAsync(t.PeerFp, PacketType.FileOffer, JsonSerializer.SerializeToUtf8Bytes(offer), ct)
                      .ConfigureAwait(false);
            if (!resume) { t.State = TransferState.Offering; Report(t, force: true); }

            long offset;
            try
            {
                offset = await acceptTcs.Task.WaitAsync(resume ? ResumeAcceptTimeout : OfferTimeout, ct)
                                        .ConfigureAwait(false);
            }
            catch (TimeoutException) when (!resume)
            {
                throw new TransferException(TransferError.Timeout, "no response");
            }

            if (offset < 0)
            {
                var reason = (RejectReason)(-offset - 1);
                throw reason switch
                {
                    RejectReason.DiskFull => new TransferException(TransferError.DiskFull, "receiver disk full"),
                    RejectReason.Busy => new TransferException(TransferError.Busy, "busy"),
                    _ => new TransferException(TransferError.Rejected, "rejected"),
                };
            }
            offset = Math.Clamp(offset, 0, t.Size);
            t.EverAccepted = true;
            if (t.ResumedFrom < 0) t.ResumedFrom = offset;

            // ---- 2. Bơm chunk ----
            await using var fs = new FileStream(t.Path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, bufferSize: 0,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            long pos = offset;
            await HashUpToAsync(t, fs, pos, ct).ConfigureAwait(false); // resume: băm phần đầu đã có
            t.Done = pos;
            t.State = TransferState.Transferring;
            t.LastReportTick = Environment.TickCount64;
            t.LastReportBytes = pos;
            Report(t, force: true);

            while (true)
            {
                while (pos < t.Size)
                {
                    ct.ThrowIfCancellationRequested();
                    long seek = Interlocked.Exchange(ref t.SeekRequest, -1);
                    if (seek >= 0 && seek <= t.Size && seek != pos)
                    {
                        pos = seek; // bên nhận yêu cầu tua (thiếu chunk) — dữ liệu ở offset này không đổi
                        await HashUpToAsync(t, fs, pos, ct).ConfigureAwait(false);
                    }

                    int want = (int)Math.Min(ChunkSize, t.Size - pos);
                    byte[] buf = ArrayPool<byte>.Shared.Rent(ChunkHeader + want);
                    int read;
                    try
                    {
                        t.Id.TryWriteBytes(buf.AsSpan(0, 16));
                        BinaryPrimitives.WriteInt64LittleEndian(buf.AsSpan(16, 8), pos);
                        fs.Position = pos;
                        read = await fs.ReadAsync(buf.AsMemory(ChunkHeader, want), ct).ConfigureAwait(false);
                        if (read <= 0) throw new IOException("File nguồn bị thu nhỏ trong lúc gửi");

                        if (pos + read > t.HashedUpTo)
                        {
                            int skip = (int)Math.Max(0, t.HashedUpTo - pos);
                            t.Hash.AppendData(buf, ChunkHeader + skip, read - skip);
                            t.HashedUpTo = pos + read;
                        }
                    }
                    catch
                    {
                        ArrayPool<byte>.Shared.Return(buf);
                        throw;
                    }

                    await _msg.SendBulkAsync(t.PeerFp, PacketType.FileChunk, buf, ChunkHeader + read, ct)
                              .ConfigureAwait(false); // buf thuộc về messaging từ đây
                    pos += read;
                    t.Done = pos;
                    Report(t);
                }

                // ---- 3. Hoàn tất + chờ bên nhận xác nhận SHA-256 ----
                byte[] hash = t.Hash.GetCurrentHash();
                var resultTcs = new TaskCompletionSource<ResultStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
                t.ResultTcs = resultTcs;
                byte[] complete = new byte[16 + 32];
                t.Id.TryWriteBytes(complete);
                hash.CopyTo(complete, 16);
                await _msg.SendAsync(t.PeerFp, PacketType.FileComplete, complete, ct).ConfigureAwait(false);

                t.State = TransferState.Verifying;
                t.Speed = 0;
                Report(t, force: true);

                // Chờ kết quả, nhưng nếu bên nhận báo thiếu chunk (seek) thì quay lại bơm tiếp
                var deadline = Task.Delay(ResultTimeout, ct);
                while (!resultTcs.Task.IsCompleted)
                {
                    if (Interlocked.Read(ref t.SeekRequest) >= 0) break;
                    var w = await Task.WhenAny(resultTcs.Task, deadline, Task.Delay(100, ct)).ConfigureAwait(false);
                    if (w == deadline) throw new TimeoutException("receiver did not confirm");
                }
                if (!resultTcs.Task.IsCompleted)
                {
                    t.State = TransferState.Transferring;
                    continue; // quay lại vòng bơm với vị trí tua mới
                }

                ResultStatus status = await resultTcs.Task.ConfigureAwait(false);
                if (status == ResultStatus.HashMismatch)
                    throw new TransferException(TransferError.Integrity, "SHA-256 mismatch");
                if (status != ResultStatus.Ok)
                    throw new TransferException(TransferError.Io, "receiver I/O error");

                t.State = TransferState.Completed;
                t.Detail = Convert.ToHexString(hash);
                return;
            }
        }

        /// <summary>Băm phần file [HashedUpTo, target) nếu chưa băm (dùng khi resume từ giữa file).</summary>
        private static async Task HashUpToAsync(Outgoing t, FileStream fs, long target, CancellationToken ct)
        {
            if (t.HashedUpTo >= target) return;
            byte[] buf = ArrayPool<byte>.Shared.Rent(1 << 20);
            try
            {
                fs.Position = t.HashedUpTo;
                while (t.HashedUpTo < target)
                {
                    int want = (int)Math.Min(buf.Length, target - t.HashedUpTo);
                    int n = await fs.ReadAsync(buf.AsMemory(0, want), ct).ConfigureAwait(false);
                    if (n <= 0) throw new IOException("File nguồn ngắn hơn dự kiến");
                    t.Hash.AppendData(buf, 0, n);
                    t.HashedUpTo += n;
                }
            }
            finally { ArrayPool<byte>.Shared.Return(buf); }
        }

        private static bool IsTransient(Exception ex) => ex switch
        {
            TransferException => false,
            OperationCanceledException => false,
            IOException => true,           // gồm PeerUnavailableException, lỗi socket
            SocketExceptionLike => true,
            TimeoutException => true,
            ObjectDisposedException => true,
            AggregateException ae => ae.InnerExceptions.All(IsTransient),
            _ => false,
        };

        // (khớp mọi SocketException mà không cần using System.Net.Sockets ở switch)
        private abstract class SocketExceptionLike : Exception { }

        // ==================================================================
        //  BÊN NHẬN
        // ==================================================================

        public Task AcceptAsync(Guid id) => Task.Run(async () =>
        {
            if (!_in.TryGetValue(id, out var t) || t.State != TransferState.AwaitingDecision) return;
            t.Consented = true;
            await BeginReceiveAsync(t).ConfigureAwait(false);
        });

        public Task RejectAsync(Guid id) => Task.Run(async () =>
        {
            if (!_in.TryRemove(id, out var t)) return;
            t.State = TransferState.Rejected;
            Report(t, force: true);
            await SendSafe(t.PeerFp, PacketType.FileReject, RejectPayload(id, RejectReason.User)).ConfigureAwait(false);
        });

        /// <summary>Hủy một transfer (gửi hoặc nhận). Phần .part được GIỮ để resume về sau.</summary>
        public void Cancel(Guid id)
        {
            if (_out.TryGetValue(id, out var o))
            {
                try { o.Cts.Cancel(); } catch (ObjectDisposedException) { }
                o.AcceptTcs?.TrySetCanceled();
                return;
            }
            if (_in.TryRemove(id, out var t))
            {
                _ = Task.Run(async () =>
                {
                    await CloseStreamAsync(t).ConfigureAwait(false);
                    t.State = TransferState.Canceled;
                    t.Speed = 0;
                    Report(t, force: true);
                    await SendSafe(t.PeerFp, PacketType.FileCancel, id.ToByteArray()).ConfigureAwait(false);
                });
            }
        }

        private async Task BeginReceiveAsync(Incoming t)
        {
            await t.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                await CloseStreamAsyncLocked(t).ConfigureAwait(false);

                // Hai offer khác nhau đang cùng ghi một .part? (cùng file gửi 2 lần song song)
                if (_in.Values.Any(o => o != t && o.PartPath == t.PartPath && o.Stream is not null))
                {
                    _in.TryRemove(t.Id, out _);
                    t.State = TransferState.Failed; t.Error = TransferError.Busy;
                    Report(t, force: true);
                    _ = SendSafe(t.PeerFp, PacketType.FileReject, RejectPayload(t.Id, RejectReason.Busy));
                    return;
                }

                long offset = File.Exists(t.PartPath) ? new FileInfo(t.PartPath).Length : 0;
                if (offset > t.Size) { File.Delete(t.PartPath); offset = 0; }

                if (!HasFreeSpace(t.Size - offset))
                {
                    _in.TryRemove(t.Id, out _);
                    t.State = TransferState.Failed; t.Error = TransferError.DiskFull;
                    Report(t, force: true);
                    _ = SendSafe(t.PeerFp, PacketType.FileReject, RejectPayload(t.Id, RejectReason.DiskFull));
                    return;
                }

                // Resume: băm lại phần đã có để cuối cùng đối chiếu được SHA-256 TOÀN file
                t.Hash?.Dispose();
                t.Hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                if (offset > 0)
                {
                    t.State = TransferState.Preparing;
                    t.Done = offset;
                    Report(t, force: true);
                    await using var rs = new FileStream(t.PartPath, FileMode.Open, FileAccess.Read, FileShare.Read,
                        1 << 20, FileOptions.Asynchronous | FileOptions.SequentialScan);
                    byte[] buf = ArrayPool<byte>.Shared.Rent(1 << 20);
                    try
                    {
                        int n;
                        while ((n = await rs.ReadAsync(buf.AsMemory(0, 1 << 20)).ConfigureAwait(false)) > 0)
                            t.Hash.AppendData(buf, 0, n);
                    }
                    finally { ArrayPool<byte>.Shared.Return(buf); }
                }

                t.Stream = new FileStream(t.PartPath, FileMode.Append, FileAccess.Write, FileShare.Read,
                    bufferSize: 0, FileOptions.Asynchronous);
                t.Done = offset;
                if (t.ResumedFrom < 0) t.ResumedFrom = offset;
                t.LastResyncAt = -1;
                t.State = TransferState.Transferring;
                t.LastReportTick = Environment.TickCount64;
                t.LastReportBytes = offset;
                Report(t, force: true);

                _ = SendSafe(t.PeerFp, PacketType.FileAccept,
                    JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(t.Id, offset)));
            }
            catch (Exception ex)
            {
                _in.TryRemove(t.Id, out _);
                await CloseStreamAsyncLocked(t).ConfigureAwait(false);
                t.State = TransferState.Failed; t.Error = TransferError.Io; t.Detail = ex.Message;
                Report(t, force: true);
                _ = SendSafe(t.PeerFp, PacketType.FileCancel, t.Id.ToByteArray());
            }
            finally { t.Lock.Release(); }
        }

        private bool HasFreeSpace(long needed)
        {
            try
            {
                string? root = Path.GetPathRoot(Path.GetFullPath(SaveFolder));
                if (string.IsNullOrEmpty(root)) return true;
                return new DriveInfo(root).AvailableFreeSpace >= needed + 16 * 1024 * 1024;
            }
            catch { return true; } // ổ mạng / không xác định → cứ thử
        }

        private string PartPathFor(string peerFp, OfferMsg offer, string safeName)
        {
            string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{peerFp}|{offer.ContentKey}|{offer.Name}|{offer.Size}")), 0, 6);
            return Path.Combine(SaveFolder, $"{safeName}.{key.ToLowerInvariant()}.part");
        }

        /// <summary>
        /// AN NINH: tên file đến từ máy KHÁC = dữ liệu không tin cậy — lột bỏ mọi đường dẫn
        /// (chống path traversal "..\..\Windows\..."), ký tự cấm và tên thiết bị DOS (CON, NUL...).
        /// </summary>
        internal static string SanitizeFileName(string name)
        {
            name = Path.GetFileName(name.Replace('\\', '/').Split('/').Last());
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            name = name.Trim().TrimEnd('.');
            string stem = Path.GetFileNameWithoutExtension(name).ToUpperInvariant();
            if (stem is "CON" or "PRN" or "AUX" or "NUL" ||
                (stem.Length == 4 && (stem.StartsWith("COM") || stem.StartsWith("LPT")) && char.IsDigit(stem[3])))
                name = "_" + name;
            if (name.Length > 180) name = name[..140] + "~" + name[^20..];
            return string.IsNullOrWhiteSpace(name) ? "unnamed" : name;
        }

        // ==================================================================
        //  XỬ LÝ GÓI ĐẾN (được AWAIT trong reader loop của messaging → backpressure tự nhiên)
        // ==================================================================

        private ValueTask HandleFrameAsync(string fp, PacketType type, ReadOnlyMemory<byte> payload)
        {
            switch (type)
            {
                case PacketType.FileOffer: return HandleOfferAsync(fp, payload);
                case PacketType.FileAccept: HandleAccept(fp, payload); break;
                case PacketType.FileReject: HandleReject(fp, payload.Span); break;
                case PacketType.FileChunk: return HandleChunkAsync(fp, payload);
                case PacketType.FileComplete: return HandleCompleteAsync(fp, payload);
                case PacketType.FileCancel: HandleCancel(fp, payload.Span); break;
                case PacketType.FileResult: HandleResult(fp, payload.Span); break;
            }
            return ValueTask.CompletedTask;
        }

        private async ValueTask HandleOfferAsync(string fp, ReadOnlyMemory<byte> payload)
        {
            OfferMsg? offer;
            try { offer = JsonSerializer.Deserialize<OfferMsg>(payload.Span); }
            catch (JsonException) { return; }
            if (offer is null || offer.Id == Guid.Empty || offer.Size < 0 ||
                string.IsNullOrWhiteSpace(offer.Name) || offer.Name.Length > 1024 ||
                (offer.ContentKey?.Length ?? 0) > 64)
                return;

            // Đã nhận xong từ trước (mất kết nối đúng lúc báo kết quả) → báo bên gửi "đủ rồi"
            if (_completedIncoming.TryGetValue(offer.Id, out string? doneFp) && doneFp == fp)
            {
                _ = SendSafe(fp, PacketType.FileAccept, JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(offer.Id, offer.Size)));
                return;
            }

            if (_in.TryGetValue(offer.Id, out var existing))
            {
                if (existing.PeerFp != fp) return; // id trùng từ người khác → bỏ qua
                if (existing.Consented)
                {
                    // Bên gửi quay lại sau khi mất kết nối — người dùng ĐÃ đồng ý → tự resume
                    existing.Reconnects++;
                    _ = Task.Run(() => BeginReceiveAsync(existing));
                }
                return;
            }

            string safe = SanitizeFileName(offer.Name);
            var t = new Incoming
            {
                Id = offer.Id, PeerFp = fp, FileName = safe, Size = offer.Size,
                Offer = offer with { ContentKey = offer.ContentKey ?? "" },
                PartPath = PartPathFor(fp, offer, safe), State = TransferState.AwaitingDecision,
            };
            try
            {
                if (File.Exists(t.PartPath))
                    t.ResumedFrom = Math.Min(new FileInfo(t.PartPath).Length, t.Size);
            }
            catch { }
            t.Done = Math.Max(0, t.ResumedFrom);
            _in[t.Id] = t;
            Report(t, force: true);
            await Task.CompletedTask;
        }

        private void HandleAccept(string fp, ReadOnlyMemory<byte> payload)
        {
            AcceptMsg? m;
            try { m = JsonSerializer.Deserialize<AcceptMsg>(payload.Span); }
            catch (JsonException) { return; }
            if (m is null || !_out.TryGetValue(m.Id, out var t) || t.PeerFp != fp) return;

            var tcs = t.AcceptTcs;
            if (tcs is not null && !tcs.Task.IsCompleted) tcs.TrySetResult(m.Offset);
            else Interlocked.Exchange(ref t.SeekRequest, m.Offset); // yêu cầu tua giữa chừng
        }

        private void HandleReject(string fp, ReadOnlySpan<byte> p)
        {
            if (p.Length < 16) return;
            var id = new Guid(p[..16]);
            byte reason = p.Length > 16 ? p[16] : (byte)0;
            if (_out.TryGetValue(id, out var t) && t.PeerFp == fp)
                t.AcceptTcs?.TrySetResult(-1 - reason);
        }

        private async ValueTask HandleChunkAsync(string fp, ReadOnlyMemory<byte> payload)
        {
            if (payload.Length < ChunkHeader) return;
            var id = new Guid(payload.Span[..16]);
            long off = BinaryPrimitives.ReadInt64LittleEndian(payload.Span.Slice(16, 8));
            ReadOnlyMemory<byte> data = payload[ChunkHeader..];

            if (!_in.TryGetValue(id, out var t) || t.PeerFp != fp) return;

            await t.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (t.Stream is null || t.State != TransferState.Transferring) return;
                if (off < t.Done) return; // trùng (gửi lại sau khi tua) → bỏ, idempotent
                if (off > t.Done)
                {
                    // Thiếu dữ liệu ở giữa (gói nằm trên kết nối đã chết) → xin tua về đúng chỗ
                    if (t.LastResyncAt != t.Done)
                    {
                        t.LastResyncAt = t.Done;
                        _ = SendSafe(fp, PacketType.FileAccept,
                            JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(id, t.Done)));
                    }
                    return;
                }
                if (off + data.Length > t.Size) return; // vượt kích thước đã đồng ý → chống làm đầy ổ đĩa

                try
                {
                    await t.Stream.WriteAsync(data).ConfigureAwait(false);
                }
                catch (IOException ex)
                {
                    _in.TryRemove(id, out _);
                    await CloseStreamAsyncLocked(t).ConfigureAwait(false);
                    t.State = TransferState.Failed;
                    t.Error = IsDiskFull(ex) ? TransferError.DiskFull : TransferError.Io;
                    t.Detail = ex.Message;
                    Report(t, force: true);
                    _ = SendSafe(fp, PacketType.FileCancel, id.ToByteArray());
                    return;
                }
                t.Hash!.AppendData(data.Span);
                t.Done += data.Length;
                Report(t);
            }
            finally { t.Lock.Release(); }
        }

        private static bool IsDiskFull(IOException ex)
            => (ex.HResult & 0xFFFF) is 0x70 or 0x27; // ERROR_DISK_FULL / ERROR_HANDLE_DISK_FULL

        private async ValueTask HandleCompleteAsync(string fp, ReadOnlyMemory<byte> payload)
        {
            if (payload.Length < 16 + 32) return;
            var id = new Guid(payload.Span[..16]);
            byte[] expected = payload.Slice(16, 32).ToArray();

            if (_completedIncoming.TryGetValue(id, out string? doneFp) && doneFp == fp)
            {
                _ = SendSafe(fp, PacketType.FileResult, ResultPayload(id, ResultStatus.Ok));
                return;
            }
            if (!_in.TryGetValue(id, out var t) || t.PeerFp != fp) return;

            await t.Lock.WaitAsync().ConfigureAwait(false);
            try
            {
                if (t.Stream is null || t.State != TransferState.Transferring) return;
                if (t.Done != t.Size)
                {
                    // Chưa đủ byte (một số chunk nằm trên kết nối đã chết) → xin tua
                    _ = SendSafe(fp, PacketType.FileAccept, JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(id, t.Done)));
                    return;
                }

                t.State = TransferState.Verifying;
                t.Speed = 0;
                Report(t, force: true);
                await CloseStreamAsyncLocked(t).ConfigureAwait(false);
                byte[] actual = t.Hash!.GetHashAndReset();
                _in.TryRemove(id, out _);

                if (!CryptographicOperations.FixedTimeEquals(actual, expected))
                {
                    // Dữ liệu sai (phần .part cũ không khớp...) → xóa, bắt đầu lại sạch sẽ lần sau
                    try { File.Delete(t.PartPath); } catch { }
                    t.State = TransferState.Failed;
                    t.Error = TransferError.Integrity;
                    Report(t, force: true);
                    _ = SendSafe(fp, PacketType.FileResult, ResultPayload(id, ResultStatus.HashMismatch));
                    return;
                }

                string finalPath = MakeUniquePath(Path.Combine(SaveFolder, t.FileName));
                File.Move(t.PartPath, finalPath);
                _completedIncoming[id] = fp;
                t.LocalPath = finalPath;
                t.State = TransferState.Completed;
                t.Detail = Convert.ToHexString(actual);
                Report(t, force: true);
                _ = SendSafe(fp, PacketType.FileResult, ResultPayload(id, ResultStatus.Ok));
            }
            catch (Exception ex)
            {
                _in.TryRemove(id, out _);
                t.State = TransferState.Failed; t.Error = TransferError.Io; t.Detail = ex.Message;
                Report(t, force: true);
                _ = SendSafe(fp, PacketType.FileResult, ResultPayload(id, ResultStatus.IoError));
            }
            finally { t.Lock.Release(); }
        }

        private void HandleCancel(string fp, ReadOnlySpan<byte> p)
        {
            if (p.Length < 16) return;
            var id = new Guid(p[..16]);

            if (_out.TryGetValue(id, out var o) && o.PeerFp == fp)
            {
                o.CanceledByPeer = true;
                try { o.Cts.Cancel(); } catch (ObjectDisposedException) { }
            }

            if (_in.TryGetValue(id, out var t) && t.PeerFp == fp && _in.TryRemove(id, out _))
            {
                _ = Task.Run(async () =>
                {
                    await CloseStreamAsync(t).ConfigureAwait(false);
                    t.State = TransferState.Canceled;
                    t.Detail = "peer";
                    t.Speed = 0;
                    Report(t, force: true);
                });
            }
        }

        private void HandleResult(string fp, ReadOnlySpan<byte> p)
        {
            if (p.Length < 17) return;
            var id = new Guid(p[..16]);
            if (_out.TryGetValue(id, out var t) && t.PeerFp == fp)
                t.ResultTcs?.TrySetResult((ResultStatus)p[16]);
        }

        /// <summary>Mất phiên với MỘT peer → chỉ tạm dừng transfer của peer đó (giữ .part).</summary>
        private void OnSessionLost(string fp, CloseReason reason)
        {
            var lost = new PeerUnavailableException("Mất kết nối", reason);
            foreach (var o in _out.Values.Where(o => o.PeerFp == fp))
            {
                o.AcceptTcs?.TrySetException(lost);
                o.ResultTcs?.TrySetException(lost);
            }

            foreach (var t in _in.Values.Where(t => t.PeerFp == fp))
            {
                _ = Task.Run(async () =>
                {
                    await t.Lock.WaitAsync().ConfigureAwait(false);
                    try
                    {
                        if (t.State is TransferState.Transferring or TransferState.Preparing)
                        {
                            await CloseStreamAsyncLocked(t).ConfigureAwait(false);
                            t.State = TransferState.Paused;
                            t.Speed = 0;
                            Report(t, force: true);
                        }
                    }
                    finally { t.Lock.Release(); }
                });
            }
        }

        // ==================================================================
        //  TIỆN ÍCH
        // ==================================================================

        private async Task CloseStreamAsync(Incoming t)
        {
            await t.Lock.WaitAsync().ConfigureAwait(false);
            try { await CloseStreamAsyncLocked(t).ConfigureAwait(false); }
            finally { t.Lock.Release(); }
        }

        private static async Task CloseStreamAsyncLocked(Incoming t)
        {
            var s = t.Stream;
            t.Stream = null;
            if (s is null) return;
            try { await s.FlushAsync().ConfigureAwait(false); } catch { }
            try { await s.DisposeAsync().ConfigureAwait(false); } catch { }
        }

        private async Task SendSafe(string fp, PacketType type, byte[] payload)
        {
            try { await _msg.SendAsync(fp, type, payload, _cts.Token).ConfigureAwait(false); }
            catch { /* kết nối chết thì thôi — bên kia có timeout/heartbeat riêng */ }
        }

        private static byte[] RejectPayload(Guid id, RejectReason reason)
        {
            byte[] p = new byte[17];
            id.TryWriteBytes(p);
            p[16] = (byte)reason;
            return p;
        }

        private static byte[] ResultPayload(Guid id, ResultStatus status)
        {
            byte[] p = new byte[17];
            id.TryWriteBytes(p);
            p[16] = (byte)status;
            return p;
        }

        private void Report(TransferBase t, bool force = false)
        {
            long now = Environment.TickCount64;
            long dt = now - t.LastReportTick;
            if (!force && dt < ProgressIntervalMs) return; // UI không cần 2000 cập nhật/giây

            if (dt > 0 && t.State == TransferState.Transferring)
            {
                double inst = (t.Done - t.LastReportBytes) * 1000.0 / dt;
                if (inst >= 0) t.Speed = t.Speed <= 0 ? inst : t.Speed * 0.75 + inst * 0.25;
            }
            t.LastReportTick = now;
            t.LastReportBytes = t.Done;

            var snap = new TransferSnapshot(t.Id, t.PeerFp,
                t is Outgoing ? TransferDirection.Send : TransferDirection.Receive,
                t.FileName, t.Size, t.Done, t.Speed, t.State, t.Error, t.Detail, t.LocalPath,
                Math.Max(0, t.ResumedFrom), t.Reconnects);
            try { Updated?.Invoke(snap); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Transfer event] {ex}"); }
        }

        private static string MakeUniquePath(string path)
        {
            if (!File.Exists(path)) return path;
            string dir = Path.GetDirectoryName(path)!;
            string name = Path.GetFileNameWithoutExtension(path);
            string ext = Path.GetExtension(path);
            for (int i = 1; ; i++)
            {
                string candidate = Path.Combine(dir, $"{name} ({i}){ext}");
                if (!File.Exists(candidate)) return candidate;
            }
        }

        /// <summary>Dọn .part bỏ dở quá 14 ngày — không để thư mục Downloads phình mãi.</summary>
        private void CleanupStalePartFiles()
        {
            try
            {
                foreach (var f in new DirectoryInfo(SaveFolder).EnumerateFiles("*.part"))
                    if (DateTime.UtcNow - f.LastWriteTimeUtc > TimeSpan.FromDays(14))
                        f.Delete();
            }
            catch { }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _msg.SessionLost -= OnSessionLost;
            if (_msg.FrameHandler == HandleFrameAsync) _msg.FrameHandler = null;
            foreach (var o in _out.Values) { try { o.Cts.Cancel(); } catch { } }
            foreach (var t in _in.Values)
            {
                var s = t.Stream;
                t.Stream = null;
                try { s?.Dispose(); } catch { } // GIỮ .part = điểm resume
            }
        }

        private sealed class TransferException : Exception
        {
            public TransferError Error { get; }
            public TransferException(TransferError error, string message) : base(message) => Error = error;
        }
    }
}
