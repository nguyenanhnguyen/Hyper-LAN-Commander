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
    /// Truyền file theo triết lý CONSENT-FIRST + RESUME:
    ///
    ///   Sender                              Receiver
    ///   ── FileOffer {id, tên, size} ──▶    (UI hỏi người dùng)
    ///   ◀─ FileAccept {id, offset} ────     offset = số byte đã có từ lần trước
    ///   ── FileChunk × N (từ offset) ─▶     ghi nối vào file .part
    ///   ── FileComplete ─────────────▶      đổi tên .part → file thật
    ///
    /// RESUME không cần file meta riêng: độ dài file .part CHÍNH LÀ offset —
    /// TCP đảm bảo byte đến đúng thứ tự nên .part luôn là "khúc đầu" hợp lệ.
    /// Mất mạng giữa chừng → .part còn nguyên → lần gửi lại tự nối tiếp.
    /// </summary>
    public class FileTransferService : IDisposable
    {
        private const int ChunkSize = 64 * 1024;              // 64KB/chunk — cân bằng RAM và tốc độ
        private static readonly TimeSpan OfferTimeout = TimeSpan.FromSeconds(30);

        private readonly MessagingService _msg;
        public string SaveFolder { get; }

        // Bên GỬI: chờ Accept/Reject theo transferId
        private readonly ConcurrentDictionary<Guid, TaskCompletionSource<long>> _pendingOffers = new();
        // Bên NHẬN: các file đang ghi dở
        private readonly ConcurrentDictionary<Guid, IncomingFile> _incoming = new();

        private sealed class IncomingFile : IDisposable
        {
            public required FileOfferInfo Info { get; init; }
            public required FileStream Stream { get; init; }
            public required string PartPath { get; init; }
            public long Received;
            public void Dispose() => Stream.Dispose();
        }

        // ---------- Events cho UI ----------
        /// <summary>(ip, offer, đã có sẵn bao nhiêu byte) — UI hiện hộp thoại hỏi người dùng.</summary>
        public event Action<string, FileOfferInfo, long>? OnIncomingOffer;
        /// <summary>(tên file, byte xong, tổng byte, đang gửi?) — cập nhật progress bar.</summary>
        public event Action<string, long, long, bool>? OnProgress;
        /// <summary>(tên file / đường dẫn, đang gửi?) — hoàn tất.</summary>
        public event Action<string, bool>? OnCompleted;
        /// <summary>(tên file, lý do)</summary>
        public event Action<string, string>? OnFailed;

        public FileTransferService(MessagingService msg)
        {
            _msg = msg;
            _msg.OnFrameReceived += HandleFrame;
            _msg.OnPeerDisconnected += _ => CleanupIncomingStreams(); // giữ .part cho resume

            SaveFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Downloads", "HyperLAN");
            Directory.CreateDirectory(SaveFolder);
        }

        // ==================== BÊN GỬI ====================

        public async Task SendFileAsync(string ip, string filePath)
        {
            var info = new FileInfo(filePath);
            var offer = new FileOfferInfo(Guid.NewGuid(), info.Name, info.Length);

            var tcs = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingOffers[offer.TransferId] = tcs;

            try
            {
                await _msg.SendFrameAsync(ip, PacketType.FileOffer,
                    JsonSerializer.SerializeToUtf8Bytes(offer));

                // Chờ người bên kia BẤM ĐỒNG Ý — không gửi gì trước đó
                using var timeoutCts = new CancellationTokenSource(OfferTimeout);
                long offset;
                try
                {
                    offset = await tcs.Task.WaitAsync(timeoutCts.Token);
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

                // offset > 0 nghĩa là RESUME — seek tới đúng chỗ dang dở
                await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.Read, ChunkSize, useAsync: true);
                fs.Seek(offset, SeekOrigin.Begin);

                byte[] buffer = new byte[16 + ChunkSize]; // [16B transferId][chunk]
                offer.TransferId.TryWriteBytes(buffer.AsSpan(0, 16));

                long sent = offset;
                int read;
                while ((read = await fs.ReadAsync(buffer.AsMemory(16, ChunkSize))) > 0)
                {
                    await _msg.SendFrameAsync(ip, PacketType.FileChunk, buffer.AsMemory(0, 16 + read));
                    sent += read;
                    OnProgress?.Invoke(offer.FileName, sent, info.Length, true);
                }

                await _msg.SendFrameAsync(ip, PacketType.FileComplete,
                    offer.TransferId.ToByteArray());
                OnCompleted?.Invoke(offer.FileName, true);
            }
            catch (Exception ex)
            {
                OnFailed?.Invoke(offer.FileName, ex.Message);
            }
            finally
            {
                _pendingOffers.TryRemove(offer.TransferId, out _);
            }
        }

        // ==================== BÊN NHẬN ====================

        /// <summary>UI gọi khi người dùng bấm "Nhận". Tự phát hiện .part để resume.</summary>
        public async Task AcceptAsync(string ip, FileOfferInfo offer)
        {
            string partPath = GetPartPath(offer);
            long offset = File.Exists(partPath) ? new FileInfo(partPath).Length : 0;
            if (offset > offer.FileSize) { File.Delete(partPath); offset = 0; } // .part rác

            var stream = new FileStream(partPath, FileMode.Append, FileAccess.Write,
                FileShare.None, ChunkSize, useAsync: true);
            _incoming[offer.TransferId] = new IncomingFile
                { Info = offer, Stream = stream, PartPath = partPath, Received = offset };

            await _msg.SendFrameAsync(ip, PacketType.FileAccept,
                JsonSerializer.SerializeToUtf8Bytes(new AcceptMsg(offer.TransferId, offset)));
        }

        /// <summary>UI gọi khi người dùng bấm "Từ chối".</summary>
        public Task RejectAsync(string ip, FileOfferInfo offer)
            => _msg.SendFrameAsync(ip, PacketType.FileReject, offer.TransferId.ToByteArray());

        /// <summary>Số byte đã nhận dở từ lần trước (0 = chưa có gì) — để UI báo "sẽ tải tiếp".</summary>
        public long GetResumeOffset(FileOfferInfo offer)
        {
            string p = GetPartPath(offer);
            return File.Exists(p) ? Math.Min(new FileInfo(p).Length, offer.FileSize) : 0;
        }

        private record AcceptMsg(Guid TransferId, long Offset);

        private string GetPartPath(FileOfferInfo offer)
            => Path.Combine(SaveFolder, SanitizeFileName(offer.FileName) + ".part");

        /// <summary>
        /// AN NINH: tên file đến từ máy KHÁC = dữ liệu không tin cậy. Lột bỏ mọi
        /// đường dẫn để chống path traversal ("..\..\Windows\system32\x.dll").
        /// </summary>
        private static string SanitizeFileName(string name)
        {
            name = Path.GetFileName(name); // vứt bỏ thư mục
            foreach (char c in Path.GetInvalidFileNameChars())
                name = name.Replace(c, '_');
            return string.IsNullOrWhiteSpace(name) ? "unnamed" : name;
        }

        // ==================== XỬ LÝ GÓI ĐẾN ====================

        private async void HandleFrame(string ip, PacketType type, byte[] payload)
        {
            try
            {
                switch (type)
                {
                    case PacketType.FileOffer:
                    {
                        var offer = JsonSerializer.Deserialize<FileOfferInfo>(payload)!;
                        if (offer.FileSize < 0) return; // gói rác
                        OnIncomingOffer?.Invoke(ip, offer, GetResumeOffset(offer));
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
                        if (!_incoming.TryGetValue(id, out var file)) return; // chunk lạc

                        int dataLen = payload.Length - 16;
                        // Không nhận quá size đã khai — chống peer gửi tràn đĩa
                        if (file.Received + dataLen > file.Info.FileSize) return;

                        await file.Stream.WriteAsync(payload.AsMemory(16, dataLen));
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
            // Đóng stream đang ghi dở nhưng GIỮ .part — đó chính là điểm resume
            foreach (var kv in _incoming)
                if (_incoming.TryRemove(kv.Key, out var f)) f.Dispose();
        }

        public void Dispose()
        {
            _msg.OnFrameReceived -= HandleFrame;
            CleanupIncomingStreams();
        }
    }
}
