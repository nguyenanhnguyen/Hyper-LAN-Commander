using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>
    /// TCP messaging đa kết nối, MÃ HÓA ĐẦU-CUỐI.
    ///
    /// Vòng đời một kết nối:
    ///   1. TCP connect (three-way handshake do OS thực hiện)
    ///   2. Hai bên trao gói Handshake (public key + salt + tên) — KHÔNG mã hóa
    ///   3. Mỗi bên tự tính khóa phiên AES-256 qua ECDH (khóa không đi qua mạng)
    ///   4. Từ đây MỌI frame (Text, File*) đều là ciphertext AES-GCM
    ///
    /// Frame Text/File chỉ được gửi/nhận SAU khi handshake xong (peer.Ready).
    /// Gói bị sửa trên đường truyền → GCM tag sai → đóng kết nối ngay.
    /// </summary>
    public class MessagingService : IDisposable
    {
        public const int Port = 8889;
        private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(5);

        private sealed class Peer
        {
            public required TcpClient Client { get; init; }
            public required NetworkStream Stream { get; init; }
            public SemaphoreSlim WriteLock { get; } = new(1, 1);

            // ---- Trạng thái mật mã của phiên ----
            public byte[] MySalt { get; } = RandomNumberGenerator.GetBytes(16);
            public byte[]? SessionKey;          // null = chưa bắt tay xong
            public string? Fingerprint;
            public string? RemoteName;
            public TaskCompletionSource Ready { get; } =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private record HandshakeMsg(byte[] PublicKey, byte[] Salt, string Name);

        private readonly CryptoService _crypto;
        private readonly TcpListener _listener = new(IPAddress.Any, Port);
        private readonly ConcurrentDictionary<string, Peer> _peers = new();
        // TOFU (Trust On First Use): nhớ fingerprint từng thấy ở mỗi IP trong phiên chạy app
        private readonly ConcurrentDictionary<string, string> _seenFingerprints = new();
        private readonly CancellationTokenSource _cts = new();

        public event Action<string, string>? OnTextReceived;
        public event Action<string>? OnPeerConnected;
        public event Action<string>? OnPeerDisconnected;
        public event Action<string, PacketType, byte[]>? OnFrameReceived;
        /// <summary>(ip, fingerprint, tên) — handshake thành công, danh tính đã xác thực bằng ECDH.</summary>
        public event Action<string, string, string>? OnPeerIdentified;
        /// <summary>(ip, fingerprint cũ, fingerprint mới) — CÙNG IP nhưng KHÓA KHÁC = cảnh báo đỏ.</summary>
        public event Action<string, string, string>? OnKeyChanged;

        public MessagingService(CryptoService crypto) => _crypto = crypto;

        public void StartListening()
        {
            _listener.Start();
            _ = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        TcpClient client = await _listener.AcceptTcpClientAsync(_cts.Token);
                        string ip = ((IPEndPoint)client.Client.RemoteEndPoint!).Address.ToString();
                        AddPeer(ip, client);
                        OnPeerConnected?.Invoke(ip);
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[TCP accept] {ex.Message}");
                    }
                }
            });
        }

        public Task SendTextAsync(string ip, string text)
            => SendFrameAsync(ip, PacketType.Text, Encoding.UTF8.GetBytes(text));

        /// <summary>
        /// Gửi frame đã MÃ HÓA. Tự connect nếu chưa có, tự chờ handshake xong.
        /// </summary>
        public async Task SendFrameAsync(string ip, PacketType type, ReadOnlyMemory<byte> payload)
        {
            Peer peer = await GetOrConnectAsync(ip);

            // Chặn cứng: không frame nào rời máy trước khi có khóa phiên
            await peer.Ready.Task.WaitAsync(HandshakeTimeout, _cts.Token);

            byte[] encrypted = CryptoService.Encrypt(peer.SessionKey!, payload.Span);

            await peer.WriteLock.WaitAsync(_cts.Token);
            try
            {
                await Protocol.WriteFrameAsync(peer.Stream, type, encrypted, _cts.Token);
            }
            catch
            {
                RemovePeer(ip);
                throw;
            }
            finally
            {
                peer.WriteLock.Release();
            }
        }

        private async Task<Peer> GetOrConnectAsync(string ip)
        {
            if (_peers.TryGetValue(ip, out Peer? existing))
                return existing;

            var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await client.ConnectAsync(IPAddress.Parse(ip), Port, timeout.Token);

            return AddPeer(ip, client);
        }

        private Peer AddPeer(string ip, TcpClient client)
        {
            client.NoDelay = true;
            var peer = new Peer { Client = client, Stream = client.GetStream() };

            if (_peers.TryRemove(ip, out Peer? old))
                old.Client.Close();
            _peers[ip] = peer;

            _ = Task.Run(() => ReceiveLoopAsync(ip, peer));
            _ = Task.Run(() => SendHandshakeAsync(ip, peer)); // chào trước, không đợi bên kia
            return peer;
        }

        private async Task SendHandshakeAsync(string ip, Peer peer)
        {
            try
            {
                var msg = new HandshakeMsg(_crypto.PublicKey, peer.MySalt, Dns.GetHostName());
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(msg);

                await peer.WriteLock.WaitAsync(_cts.Token);
                try
                {
                    await Protocol.WriteFrameAsync(peer.Stream, PacketType.Handshake, payload, _cts.Token);
                }
                finally { peer.WriteLock.Release(); }
            }
            catch { RemovePeer(ip); }
        }

        private async Task ReceiveLoopAsync(string ip, Peer peer)
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var (type, payload) = await Protocol.ReadFrameAsync(peer.Stream, _cts.Token);

                    if (type == PacketType.Handshake)
                    {
                        HandleHandshake(ip, peer, payload);
                        continue;
                    }

                    // Frame dữ liệu tới trước khi bắt tay xong → không có khóa → bỏ
                    if (peer.SessionKey is null) continue;

                    // Giải mã; gói bị sửa đổi sẽ ném CryptographicException
                    // → văng xuống catch → đóng kết nối (fail-closed)
                    byte[] plaintext = CryptoService.Decrypt(peer.SessionKey, payload);

                    switch (type)
                    {
                        case PacketType.Text:
                            OnTextReceived?.Invoke(ip, Encoding.UTF8.GetString(plaintext));
                            break;
                        default:
                            OnFrameReceived?.Invoke(ip, type, plaintext);
                            break;
                    }
                }
            }
            catch { /* stream đóng / gói giả mạo — fail-closed */ }
            finally
            {
                RemovePeer(ip);
            }
        }

        private void HandleHandshake(string ip, Peer peer, byte[] payload)
        {
            var msg = JsonSerializer.Deserialize<HandshakeMsg>(payload)!;

            peer.SessionKey = _crypto.DeriveSessionKey(msg.PublicKey, peer.MySalt, msg.Salt);
            peer.Fingerprint = CryptoService.ComputeFingerprint(msg.PublicKey);
            peer.RemoteName = msg.Name;

            // TOFU: cùng IP mà fingerprint khác lần trước = có kẻ chiếm IP → báo động
            if (_seenFingerprints.TryGetValue(ip, out string? known) && known != peer.Fingerprint)
                OnKeyChanged?.Invoke(ip, known, peer.Fingerprint);
            _seenFingerprints[ip] = peer.Fingerprint;

            peer.Ready.TrySetResult();
            OnPeerIdentified?.Invoke(ip, peer.Fingerprint, peer.RemoteName);
        }

        private void RemovePeer(string ip)
        {
            if (_peers.TryRemove(ip, out Peer? peer))
            {
                peer.Ready.TrySetCanceled();
                peer.Client.Close();
                OnPeerDisconnected?.Invoke(ip);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            foreach (var ip in _peers.Keys) RemovePeer(ip);
            _cts.Dispose();
        }
    }
}
