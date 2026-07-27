using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>Thông tin lời mời gửi file (đi trong gói FileOffer dưới dạng JSON).</summary>
    public record FileOfferInfo(Guid TransferId, string FileName, long FileSize);

    /// <summary>
    /// Truyền file CONSENT-FIRST + RESUME + CANCEL:
    ///
    ///   Sender                              Receiver
    ///   ── FileOffer {id, tên, size} ──▶    (UI hỏi người dùng)
    ///   ◀─ FileAccept {id, offset} ────     offset = số byte đã có từ lần trước
    ///   ── FileChunk × N (từ offset) ─▶     ghi nối vào file .part
    ///   ── FileComplete ─────────────▶      đổi tên .part → file thật
    ///
    /// HỦY GIỮA CHỪNG: bên nào bấm hủy thì gửi FileCancel; cả hai dừng và dọn
    /// trạng thái nhưng GIỮ NGUYÊN .part — nghĩa là hủy xong vẫn resume được.
    /// </summary>
    public class FileTransferService : IDisposable
    {
        private const int ChunkSize = 64 * 1024;
        private static readonly TimeSpan OfferTimeout = TimeSpan.FromSeconds(30);

        private readonly MessagingService _msg;
        public string SaveFolder { get; }

        // Bên GỬI: chờ Accept/Reject theo transferId
        private readonly ConcurrentDictionary<Guid, TaskCompletionSource<long>> _pendingOffers = new();
        // Bên GỬI: các transfer đang chạy → hủy được
        private readonly ConcurrentDictionary<Guid, (string PeerKey, CancellationTokenSource Cts)> _outgoing = new();
        // Bên NHẬN: các file đang ghi dở
        private readonly ConcurrentDictionary<Guid, IncomingFile> _incoming = new();

        private sealed class IncomingFile : IDisposable
        {
            public required FileOfferInfo Info { get; init; }
            public required FileStream Stream { get; init; }
            public required string PartPath { get; init; }
            public required string PeerKey { get; init; }
            public long Received;
            public void Dispose() => Stream.Dispose();
        }

        // ---------- Events cho UI ----------
        /// <summary>(peerKey, offer, đã có sẵn bao nhiêu byte)</summary>
        public event Action<string, FileOfferInfo, long>? OnIncomingOffer;
        /// <summary>(tên file, byte xong, tổng byte, đang gửi?)</summary>
        public event Action<string, long, long, bool>? OnProgress;
        /// <summary>(tên file / đường dẫn, đang gửi?)</summary>
        public event Action<string, bool>? OnCompleted;
        /// <summary>(tên file, lý do)</summary>
        public event Action<string, string>? OnFailed;
        /// <summary>(tên file) — transfer bị hủy (bởi mình hoặc bên kia); .part vẫn giữ để resume.</summary>
        public event Action<string>? OnCanceled;

        public FileTransferService(MessagingService msg)
        {
            _msg = msg;
            _msg.OnFrameReceived += HandleFrame;
            _msg.OnPeerDisconnected += _ => CleanupIncomingStreams();

            SaveFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads", "HyperLAN");
            Directory.CreateDirectory(SaveFolder);
        }

        // ==================== HỦY ====================

        /// <summary>UI gọi khi bấm nút ✕: hủy MỌI transfer đang chạy (gửi lẫn nhận).</summary>
        public async Task CancelAllAsync()
        {
            // Bên gửi: cancel token → vòng gửi tự thoát, tự gửi FileCancel + báo UI
            foreach (var (_, entry) in _outgoing)
                entry.Cts.Cancel();

            // Bên nhận: đóng stream (giữ .part), báo bên gửi dừng bơm chunk
            foreach (var kv in _incoming)
            {
                if (_incoming.TryRemove(kv.Key, out var file))
                {
                    file.Dispose();
                    await SendCancelSafeAsync(file.PeerKey, kv.Key);
                    OnCanceled?.Invoke(file.Info.FileName);
                }
            }
        }

        private async Task SendCancelSafeAsync(string peerKey, Guid id)
        {
            try { await _msg.SendFrameAsync(peerKey, PacketType.FileCancel, id.ToByteArray()); }
            catch { /* kết nối đã chết thì thôi — bên kia cũng tự dừng */ }
        }

        // ==================== BÊN GỬI ====================

        public async Task SendFileAsync(string peerKey, string filePath)
        {
            var info = new FileInfo(filePath);
            var offer = new FileOfferInfo(Guid.NewGuid(), info.Name, info.Length);

            var tcs = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingOffers[offer.TransferId] = tcs;
            var cts = new CancellationTokenSource();
            _outgoing[offer.TransferId] = (peerKey, cts);

            try
            {
                await _msg.SendFrameAsync(peerKey, PacketType.FileOffer,
                    JsonSerializer.SerializeToUtf8Bytes(offer));

                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token);
                timeoutCts.CancelAfter(OfferTimeout);
                long offset;
                try
                {
                    offset = await tcs.Task.WaitAsync(timeoutCts.Token);
                }
                catch (OperationCanceledException) when (cts.IsCancellationRequested)
                {
                    OnCanceled?.Invoke(offer.FileName);
                    return;
                }
                catch (OperationCanceledException)
                {
                    OnFailed?.Invoke(offer.FileName, "Bên nhận không phản hồi (timeout)");
                    return;
                }

                if (offset < 0)
                {
                    OnFailed?.Invoke(offer.FileName, "Bên nhận đã từ chối");
                    return;
                }

                await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, ChunkSize, useAsync: true);
                fs.Seek(offset, SeekOrigin.Begin);

                byte[] buffer = new byte[16 + ChunkSize];
                offer.TransferId.TryWriteBytes(buffer.AsSpan(0, 16));

                long sent = offset;
                int read;
                while ((read = await fs.ReadAsync(buffer.AsMemory(16, ChunkSize), cts.Token)) > 0)
                {
                    cts.Token.ThrowIfCancellationRequested();
                    await _msg.SendFrameAsync(peerKey, PacketType.FileChunk, buffer.AsMemory(0, 16 + read));
                    sent += read;
                    OnProgress?.Invoke(offer.FileName, sent, info.Length, true);
                }

                await _msg.SendFrameAsync(peerKey, PacketType.FileComplete,
                    offer.TransferId.ToByteArray());
                OnCompleted?.Invoke(offer.FileName, true);
            }
            catch (OperationCanceledException)
            {
                // Hủy (bởi mình hoặc bên kia gửi FileCancel) — báo bên kia cho chắc rồi báo UI
                await SendCancelSafeAsync(peerKey, offer.TransferId);
                OnCanceled?.Invoke(offer.FileName);
            }
            catch (Exception ex)
            {
                OnFailed?.Invoke(offer.FileName, ex.Message);
            }
            finally
            {
                _pendingOffers.TryRemove(offer.TransferId, out _);
                if (_outgoing.TryRemove(offer.TransferId, out var entry))
                    entry.Cts.Dispose();
            }
        }

        // ==================== BÊN NHẬN ====================

        public async Task AcceptAsync(string peerKey, FileOfferInfo offer)
        {
            string partPath = GetPartPath(offer);
            long offset = File.Exists(partPath) ? new FileInfo(partPath).Length : 0;
            if (offset > offer.FileSize) { File.Delete(partPath); offset = 0; }

            var stream = new FileStream(partPath, FileMode.Append, FileAccess.Write,
                FileShare.None, ChunkSize, useAsync: true);
            _incoming[offer.TransferId] = new IncomingFile
            { Info = offer, Stream = stream, PartPath = partPath, PeerKey = peerKey, Received = offset };

            await _msg.SendFrameAsync(peerKey, PacketType.FileAccept,
                JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(offer.TransferId, offset)));
        }

        public Task RejectAsync(string peerKey, FileOfferInfo offer)
            => _msg.SendFrameAsync(peerKey, PacketType.FileReject, offer.TransferId.ToByteArray());

        public long GetResumeOffset(FileOfferInfo offer)
        {
            string p = GetPartPath(offer);
            return File.Exists(p) ? Math.Min(new FileInfo(p).Length, offer.FileSize) : 0;
        }

        private record AcceptMsg(Guid TransferId, long Offset);

        private string GetPartPath(FileOfferInfo offer)
            => Path.Combine(SaveFolder, SanitizeFileName(offer.FileName) + ".part");

        /// <summary>
        /// AN NINH: tên file đến từ máy KHÁC = dữ liệu không tin cậy — lột bỏ mọi
        /// đường dẫn để chống path traversal.
        /// </summary>
        private static string SanitizeFileName(string name)
        {
            name = Path.GetFileName(name);
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return string.IsNullOrWhiteSpace(name) ? "unnamed" : name;
        }

        // ==================== XỬ LÝ GÓI ĐẾN ====================

        private async void HandleFrame(string peerKey, PacketType type, byte[] payload)
        {
            try
            {
                switch (type)
                {
                    case PacketType.FileOffer:
                        {
                            var offer = JsonSerializer.Deserialize<FileOfferInfo>(payload)!;
                            if (offer.FileSize < 0) return;
                            OnIncomingOffer?.Invoke(peerKey, offer, GetResumeOffset(offer));
                            break;
                        }
                    case PacketType.FileAccept:
                        {
                            var msg = JsonSerializer.Deserialize<AcceptMsg>(payload)!;
                            if (_pendingOffers.TryGetValue(msg.TransferId, out var tcs))
                                tcs.TrySetResult(msg.Offset);
                            break;
                        }
                    case PacketType.FileReject:
                        {
                            var id = new Guid(payload);
                            if (_pendingOffers.TryGetValue(id, out var tcs))
                                tcs.TrySetResult(-1);
                            break;
                        }
                    case PacketType.FileChunk:
                        {
                            var id = new Guid(payload.AsSpan(0, 16));
                            if (!_incoming.TryGetValue(id, out var file)) return;

                            int dataLen = payload.Length - 16;
                            if (file.Received + dataLen > file.Info.FileSize) return;

                            try
                            {
                                await file.Stream.WriteAsync(payload.AsMemory(16, dataLen));
                            }
                            catch (ObjectDisposedException)
                            {
                                return; // transfer vừa bị hủy trong lúc chunk này đang ghi — im lặng bỏ
                            }

                            // RACE GUARD: nếu transfer bị hủy TRONG LÚC đang await ở trên,
                            // tuyệt đối không bắn OnProgress nữa — kẻo UI hiện lại progress bar
                            // vừa được lệnh hủy ẩn đi.
                            if (!_incoming.ContainsKey(id)) return;

                            file.Received += dataLen;
                            OnProgress?.Invoke(file.Info.FileName, file.Received, file.Info.FileSize, false);
                            break;
                        }
                    case PacketType.FileComplete:
                        {
                            var id = new Guid(payload);
                            if (!_incoming.TryRemove(id, out var file)) return;

                            await file.Stream.FlushAsync();
                            file.Dispose();

                            string finalPath = MakeUniquePath(
                                Path.Combine(SaveFolder, SanitizeFileName(file.Info.FileName)));
                            File.Move(file.PartPath, finalPath);
                            OnCompleted?.Invoke(finalPath, false);
                            break;
                        }
                    case PacketType.FileCancel:
                        {
                            var id = new Guid(payload);

                            // Mình đang GỬI transfer này → dừng vòng gửi
                            if (_outgoing.TryGetValue(id, out var entry))
                                entry.Cts.Cancel();

                            // Mình đang NHẬN transfer này → đóng stream, giữ .part
                            if (_incoming.TryRemove(id, out var file))
                            {
                                file.Dispose();
                                OnCanceled?.Invoke(file.Info.FileName);
                            }
                            break;
                        }
                }
            }
            catch (Exception ex)
            {
                OnFailed?.Invoke("(file)", ex.Message);
            }
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

        private void CleanupIncomingStreams()
        {
            foreach (var kv in _incoming)
                if (_incoming.TryRemove(kv.Key, out var f)) f.Dispose(); // GIỮ .part = điểm resume
        }

        public void Dispose()
        {
            _msg.OnFrameReceived -= HandleFrame;
            foreach (var (_, entry) in _outgoing) entry.Cts.Cancel();
            CleanupIncomingStreams();
        }
    }
}