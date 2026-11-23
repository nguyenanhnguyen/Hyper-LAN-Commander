using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Sockets;
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
        Offering,          // gá»­i: chá» bÃªn kia Ä‘á»“ng Ã½
        AwaitingDecision,  // nháº­n: chá» ngÆ°á»i dÃ¹ng báº¥m Nháº­n / Tá»« chá»‘i
        Preparing,         // nháº­n: Ä‘ang bÄƒm láº¡i pháº§n .part cÃ³ sáºµn trÆ°á»›c khi resume
        Transferring,
        Reconnecting,      // gá»­i: máº¥t káº¿t ná»‘i â†’ Ä‘ang tá»± káº¿t ná»‘i láº¡i Ä‘á»ƒ resume
        Paused,            // nháº­n: máº¥t káº¿t ná»‘i â†’ giá»¯ .part, chá» bÃªn gá»­i quay láº¡i
        Verifying,         // Ä‘ang Ä‘á»‘i chiáº¿u SHA-256
        Completed,
        Rejected,
        Canceled,
        Failed,
    }

    public enum TransferError { None, Timeout, Rejected, Integrity, DiskFull, Io, PeerGone, Busy }

    /// <summary>áº¢nh chá»¥p báº¥t biáº¿n tráº¡ng thÃ¡i má»™t transfer â€” an toÃ n Ä‘á»ƒ chuyá»ƒn sang UI thread.</summary>
    public sealed record TransferSnapshot(
        Guid Id, string PeerFingerprint, TransferDirection Direction, string FileName, long Size,
        long Done, double BytesPerSecond, TransferState State, TransferError Error, string? Detail,
        string? LocalPath, long ResumedFrom, int Reconnects);

    /// <summary>
    /// Truyá»n file CONSENT-FIRST + RESUME Tá»° Äá»˜NG + KIá»‚M TOÃ€N Váº¸N Äáº¦U-CUá»I:
    ///
    ///   Sender                                   Receiver
    ///   â”€â”€ FileOffer {id, tÃªn, size, key} â”€â”€â–¶     (tháº» "Nháº­n / Tá»« chá»‘i" trong khung chat)
    ///   â—€â”€ FileAccept {id, offset} â”€â”€â”€â”€â”€â”€â”€â”€â”€      offset = Ä‘á»™ dÃ i .part cÃ³ sáºµn â†’ RESUME
    ///   â”€â”€ FileChunk {id, offset, data} Ã— N â”€â–¶    chá»‰ ghi khi offset == sá»‘ byte Ä‘Ã£ cÃ³
    ///   â”€â”€ FileComplete {id, SHA-256} â”€â”€â”€â”€â”€â”€â–¶     Ä‘á»‘i chiáº¿u SHA-256 toÃ n file
    ///   â—€â”€ FileResult {id, OK | sai hash} â”€â”€      .part â†’ Ä‘á»•i tÃªn thÃ nh file tháº­t
    ///
    /// â€¢ .part gáº¯n vá»›i Ná»˜I DUNG (ngÆ°á»i gá»­i + tÃªn + kÃ­ch thÆ°á»›c + thá»i Ä‘iá»ƒm sá»­a) chá»© khÃ´ng chá»‰ tÃªn:
    ///   gá»­i má»™t file KHÃC cÃ¹ng tÃªn sáº½ khÃ´ng bá»‹ ná»‘i nháº§m vÃ o pháº§n dá»Ÿ cá»§a file cÅ©.
    /// â€¢ Chunk mang offset tuyá»‡t Ä‘á»‘i â†’ ghi idempotent: chunk trÃ¹ng bá»‹ bá», chunk vÆ°á»£t (máº¥t gÃ³i
    ///   khi Ä‘á»•i káº¿t ná»‘i) â†’ bÃªn nháº­n gá»­i láº¡i FileAccept nhÆ° má»™t "yÃªu cáº§u tua" (giá»‘ng ACK tÃ­ch lÅ©y).
    /// â€¢ Máº¥t máº¡ng giá»¯a chá»«ng â†’ bÃªn gá»­i tá»± káº¿t ná»‘i láº¡i (backoff) tá»›i Báº¤T Ká»² Ä‘á»‹a chá»‰ má»›i nÃ o cá»§a
    ///   peer, gá»­i láº¡i offer cÃ¹ng id; bÃªn nháº­n nháº­n ra transfer Ä‘Ã£ Ä‘Æ°á»£c Ä‘á»“ng Ã½ â†’ tá»± resume,
    ///   khÃ´ng há»i láº¡i ngÆ°á»i dÃ¹ng. Trong suá»‘t vá»›i ngÆ°á»i dÃ¹ng: chá»‰ tháº¥y "Äang káº¿t ná»‘i láº¡iâ€¦".
    /// â€¢ SHA-256 toÃ n file Ä‘Æ°á»£c tÃ­nh dáº§n trong lÃºc truyá»n (khÃ´ng Ä‘á»c file thÃªm láº§n nÃ o).
    /// </summary>
    public sealed class FileTransferService : IDisposable
    {
        // 128KB: đủ lớn để overhead mỗi khung không đáng kể (đã bão hòa Gigabit), đủ nhỏ để một gói
        // chat chen vào chỉ phải chờ tối đa ~1 chunk (đo được: 1–2ms trễ chat khi đang đẩy file).
        public const int ChunkSize = 128 * 1024;
        private const int ChunkHeader = 16 + 8;
        private static readonly TimeSpan OfferTimeout = TimeSpan.FromMinutes(3);
        private static readonly TimeSpan ResumeAcceptTimeout = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan ResultTimeout = TimeSpan.FromSeconds(60);
        private static readonly TimeSpan ReconnectWindow = TimeSpan.FromMinutes(3);
        private const int ProgressIntervalMs = 150;

        private static readonly PacketType[] FileTypes =
        {
            PacketType.FileOffer, PacketType.FileAccept, PacketType.FileReject, PacketType.FileChunk,
            PacketType.FileComplete, PacketType.FileCancel, PacketType.FileResult,
        };

        private enum RejectReason : byte { User = 0, DiskFull = 1, Busy = 2, Invalid = 3 }
        private enum ResultStatus : byte { Ok = 0, HashMismatch = 1, IoError = 2 }

        private sealed record OfferMsg(Guid Id, string Name, long Size, string ContentKey, bool Resume);
        private sealed record AcceptMsg(Guid Id, long Offset);

        private readonly MessagingService _msg;
        public string SaveFolder { get; }

        private readonly ConcurrentDictionary<Guid, Outgoing> _out = new();
        private readonly ConcurrentDictionary<Guid, Incoming> _in = new();
        private readonly ConcurrentDictionary<Guid, string> _completedIncoming = new(); // id â†’ fp
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

            // Ä‘o tá»‘c Ä‘á»™ (EWMA)
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
            _msg.RegisterHandler(HandleFrameAsync, FileTypes);
            _msg.SessionLost += OnSessionLost;
            _ = Task.Run(CleanupStalePartFiles);
        }

        // ==================================================================
        //  BÃŠN Gá»¬I
        // ==================================================================

        public Guid StartSend(string peerFp, string filePath)
        {
            var fi = new FileInfo(filePath);
            if (!fi.Exists) throw new FileNotFoundException(filePath);

            // contentKey: dáº¥u vÃ¢n tay "phiÃªn báº£n file" â€” Ä‘á»•i ná»™i dung (mtime/size) lÃ  Ä‘á»•i key
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
                        // Máº¡ng rá»›t giá»¯a chá»«ng â†’ káº¿t ná»‘i láº¡i vÃ  resume, KHÃ”NG lÃ m phiá»n ngÆ°á»i dÃ¹ng
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
                    _ = SendSafe(t.PeerFp, PacketType.FileCancel, t.Id.ToByteArray()); // rÃºt láº¡i lá»i má»i
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
            // ---- 1. Offer & chá» Ä‘á»“ng Ã½ ----
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

            // ---- 2. BÆ¡m chunk ----
            await using var fs = new FileStream(t.Path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, bufferSize: 0,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            long pos = offset;
            await HashUpToAsync(t, fs, pos, ct).ConfigureAwait(false); // resume: bÄƒm pháº§n Ä‘áº§u Ä‘Ã£ cÃ³
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
                        pos = seek; // bÃªn nháº­n yÃªu cáº§u tua (thiáº¿u chunk) â€” dá»¯ liá»‡u á»Ÿ offset nÃ y khÃ´ng Ä‘á»•i
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
                        if (read <= 0) throw new IOException("File nguá»“n bá»‹ thu nhá» trong lÃºc gá»­i");

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
                              .ConfigureAwait(false); // buf thuá»™c vá» messaging tá»« Ä‘Ã¢y
                    pos += read;
                    t.Done = pos;
                    Report(t);
                }

                // ---- 3. HoÃ n táº¥t + chá» bÃªn nháº­n xÃ¡c nháº­n SHA-256 ----
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

                // Chá» káº¿t quáº£, nhÆ°ng náº¿u bÃªn nháº­n bÃ¡o thiáº¿u chunk (seek) thÃ¬ quay láº¡i bÆ¡m tiáº¿p
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
                    continue; // quay láº¡i vÃ²ng bÆ¡m vá»›i vá»‹ trÃ­ tua má»›i
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

        /// <summary>BÄƒm pháº§n file [HashedUpTo, target) náº¿u chÆ°a bÄƒm (dÃ¹ng khi resume tá»« giá»¯a file).</summary>
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
                    if (n <= 0) throw new IOException("File nguá»“n ngáº¯n hÆ¡n dá»± kiáº¿n");
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
            IOException => true,           // gá»“m PeerUnavailableException, lá»—i socket
            SocketException => true,
            TimeoutException => true,
            ObjectDisposedException => true,
            AggregateException ae => ae.InnerExceptions.All(IsTransient),
            _ => false,
        };

        // ==================================================================
        //  BÃŠN NHáº¬N
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

        /// <summary>Há»§y má»™t transfer (gá»­i hoáº·c nháº­n). Pháº§n .part Ä‘Æ°á»£c GIá»® Ä‘á»ƒ resume vá» sau.</summary>
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

                // Hai offer khÃ¡c nhau Ä‘ang cÃ¹ng ghi má»™t .part? (cÃ¹ng file gá»­i 2 láº§n song song)
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

                // Resume: bÄƒm láº¡i pháº§n Ä‘Ã£ cÃ³ Ä‘á»ƒ cuá»‘i cÃ¹ng Ä‘á»‘i chiáº¿u Ä‘Æ°á»£c SHA-256 TOÃ€N file
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
            catch { return true; } // á»• máº¡ng / khÃ´ng xÃ¡c Ä‘á»‹nh â†’ cá»© thá»­
        }

        private string PartPathFor(string peerFp, OfferMsg offer, string safeName)
        {
            string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
                $"{peerFp}|{offer.ContentKey}|{offer.Name}|{offer.Size}")), 0, 6);
            return Path.Combine(SaveFolder, $"{safeName}.{key.ToLowerInvariant()}.part");
        }

        /// <summary>
        /// AN NINH: tÃªn file Ä‘áº¿n tá»« mÃ¡y KHÃC = dá»¯ liá»‡u khÃ´ng tin cáº­y â€” lá»™t bá» má»i Ä‘Æ°á»ng dáº«n
        /// (chá»‘ng path traversal "..\..\Windows\..."), kÃ½ tá»± cáº¥m vÃ  tÃªn thiáº¿t bá»‹ DOS (CON, NUL...).
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
        //  Xá»¬ LÃ GÃ“I Äáº¾N (Ä‘Æ°á»£c AWAIT trong reader loop cá»§a messaging â†’ backpressure tá»± nhiÃªn)
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

        private ValueTask HandleOfferAsync(string fp, ReadOnlyMemory<byte> payload)
        {
            HandleOffer(fp, payload);
            return ValueTask.CompletedTask;
        }

        private void HandleOffer(string fp, ReadOnlyMemory<byte> payload)
        {
            OfferMsg? offer;
            try { offer = JsonSerializer.Deserialize<OfferMsg>(payload.Span); }
            catch (JsonException) { return; }
            if (offer is null || offer.Id == Guid.Empty || offer.Size < 0 ||
                string.IsNullOrWhiteSpace(offer.Name) || offer.Name.Length > 1024 ||
                (offer.ContentKey?.Length ?? 0) > 64)
                return;

            // ÄÃ£ nháº­n xong tá»« trÆ°á»›c (máº¥t káº¿t ná»‘i Ä‘Ãºng lÃºc bÃ¡o káº¿t quáº£) â†’ bÃ¡o bÃªn gá»­i "Ä‘á»§ rá»“i"
            if (_completedIncoming.TryGetValue(offer.Id, out string? doneFp) && doneFp == fp)
            {
                _ = SendSafe(fp, PacketType.FileAccept, JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(offer.Id, offer.Size)));
                return;
            }

            if (_in.TryGetValue(offer.Id, out var existing))
            {
                if (existing.PeerFp != fp) return; // id trÃ¹ng tá»« ngÆ°á»i khÃ¡c â†’ bá» qua
                if (existing.Consented)
                {
                    // BÃªn gá»­i quay láº¡i sau khi máº¥t káº¿t ná»‘i â€” ngÆ°á»i dÃ¹ng ÄÃƒ Ä‘á»“ng Ã½ â†’ tá»± resume
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
        }

        private void HandleAccept(string fp, ReadOnlyMemory<byte> payload)
        {
            AcceptMsg? m;
            try { m = JsonSerializer.Deserialize<AcceptMsg>(payload.Span); }
            catch (JsonException) { return; }
            if (m is null || !_out.TryGetValue(m.Id, out var t) || t.PeerFp != fp) return;

            var tcs = t.AcceptTcs;
            if (tcs is not null && !tcs.Task.IsCompleted) tcs.TrySetResult(m.Offset);
            else Interlocked.Exchange(ref t.SeekRequest, m.Offset); // yÃªu cáº§u tua giá»¯a chá»«ng
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
                if (ResumeIfPausedLocked(t)) return;
                if (t.Stream is null || t.State != TransferState.Transferring) return;
                if (off < t.Done) return; // trÃ¹ng (gá»­i láº¡i sau khi tua) â†’ bá», idempotent
                if (off > t.Done)
                {
                    // Thiáº¿u dá»¯ liá»‡u á»Ÿ giá»¯a (gÃ³i náº±m trÃªn káº¿t ná»‘i Ä‘Ã£ cháº¿t) â†’ xin tua vá» Ä‘Ãºng chá»—
                    if (t.LastResyncAt != t.Done)
                    {
                        t.LastResyncAt = t.Done;
                        _ = SendSafe(fp, PacketType.FileAccept,
                            JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(id, t.Done)));
                    }
                    return;
                }
                if (off + data.Length > t.Size) return; // vÆ°á»£t kÃ­ch thÆ°á»›c Ä‘Ã£ Ä‘á»“ng Ã½ â†’ chá»‘ng lÃ m Ä‘áº§y á»• Ä‘Ä©a

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

        /// <summary>
        /// Táº§ng messaging tá»± káº¿t ná»‘i láº¡i TRONG SUá»T, nÃªn bÃªn gá»­i cÃ³ thá»ƒ cá»© tháº¿ bÆ¡m chunk tiáº¿p qua
        /// káº¿t ná»‘i má»›i mÃ  khÃ´ng biáº¿t bÃªn nháº­n Ä‘Ã£ táº¡m dá»«ng. Tháº¥y dá»¯ liá»‡u Ä‘áº¿n cho má»™t transfer Ä‘ang
        /// Paused (Ä‘Ã£ Ä‘Æ°á»£c Ä‘á»“ng Ã½) = bÃªn gá»­i Ä‘Ã£ quay láº¡i â†’ má»Ÿ láº¡i .part vÃ  gá»­i resync (FileAccept
        /// vá»›i offset tháº­t) Ä‘á»ƒ bÃªn gá»­i tua vá» Ä‘Ãºng chá»—. Gá»i khi Ä‘ang giá»¯ t.Lock.
        /// </summary>
        private bool ResumeIfPausedLocked(Incoming t)
        {
            if (t.State != TransferState.Paused || !t.Consented) return false;
            t.State = TransferState.Preparing; // cháº·n cÃ¡c chunk tiáº¿p theo kÃ­ch hoáº¡t láº§n ná»¯a
            t.Reconnects++;
            _ = Task.Run(() => BeginReceiveAsync(t));
            return true;
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
                if (ResumeIfPausedLocked(t)) return;
                if (t.Stream is null || t.State != TransferState.Transferring) return;
                if (t.Done != t.Size)
                {
                    // ChÆ°a Ä‘á»§ byte (má»™t sá»‘ chunk náº±m trÃªn káº¿t ná»‘i Ä‘Ã£ cháº¿t) â†’ xin tua
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
                    // Dá»¯ liá»‡u sai (pháº§n .part cÅ© khÃ´ng khá»›p...) â†’ xÃ³a, báº¯t Ä‘áº§u láº¡i sáº¡ch sáº½ láº§n sau
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

        /// <summary>Máº¥t phiÃªn vá»›i Má»˜T peer â†’ chá»‰ táº¡m dá»«ng transfer cá»§a peer Ä‘Ã³ (giá»¯ .part).</summary>
        private void OnSessionLost(string fp, CloseReason reason)
        {
            var lost = new PeerUnavailableException("Máº¥t káº¿t ná»‘i", reason);
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
        //  TIá»†N ÃCH
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
            catch { /* káº¿t ná»‘i cháº¿t thÃ¬ thÃ´i â€” bÃªn kia cÃ³ timeout/heartbeat riÃªng */ }
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
            if (!force && dt < ProgressIntervalMs) return; // UI khÃ´ng cáº§n 2000 cáº­p nháº­t/giÃ¢y

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

        /// <summary>Dá»n .part bá» dá»Ÿ quÃ¡ 14 ngÃ y â€” khÃ´ng Ä‘á»ƒ thÆ° má»¥c Downloads phÃ¬nh mÃ£i.</summary>
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
            _msg.UnregisterHandler(FileTypes);
            foreach (var o in _out.Values) { try { o.Cts.Cancel(); } catch { } }
            foreach (var t in _in.Values)
            {
                var s = t.Stream;
                t.Stream = null;
                try { s?.Dispose(); } catch { } // GIá»® .part = Ä‘iá»ƒm resume
            }
        }

        private sealed class TransferException : Exception
        {
            public TransferError Error { get; }
            public TransferException(TransferError error, string message) : base(message) => Error = error;
        }
    }
}
