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
    /// ĐỊNH DANH PEER = "ip:port" (endpoint) thay vì chỉ IP.
    /// Nhờ vậy nhiều instance CÙNG IP (loopback test trên 1 máy) vẫn phân biệt
    /// được nhau. Cổng lắng nghe của mỗi bên được mang trong gói Handshake,
    /// nên bên nhận biết được cổng THẬT của bên kia (không phải cổng nguồn tạm).
    ///
    /// Cổng lắng nghe đọc từ biến môi trường HLC_PORT (mặc định 8889) — đặt
    /// HLC_PORT=8890 cho instance thứ 2 khi test trên cùng máy.
    /// </summary>
    public class MessagingService : IDisposable
    {
        public const int DefaultPort = 8889;
        private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(5);

        public int ListenPort { get; }

        private sealed class Peer
        {
            public required TcpClient Client { get; init; }
            public required NetworkStream Stream { get; init; }
            public SemaphoreSlim WriteLock { get; } = new(1, 1);

            public string? Key;                 // "ip:port" — null cho tới khi handshake xong (kết nối đến)
            public byte[] MySalt { get; } = RandomNumberGenerator.GetBytes(16);
            public byte[]? SessionKey;
            public string? Fingerprint;
            public string? RemoteName;
            public TaskCompletionSource Ready { get; } =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
        }

        private record HandshakeMsg(byte[] PublicKey, byte[] Salt, string Name, int ListenPort);

        private readonly CryptoService _crypto;
        private readonly TcpListener _listener;
        private readonly ConcurrentDictionary<string, Peer> _peers = new();
        private readonly ConcurrentDictionary<string, string> _seenFingerprints = new();
        private readonly CancellationTokenSource _cts = new();

        public event Action<string, string>? OnTextReceived;
        public event Action<string>? OnPeerConnected;
        public event Action<string>? OnPeerDisconnected;
        public event Action<string, PacketType, byte[]>? OnFrameReceived;
        public event Action<string, string, string>? OnPeerIdentified;   // key, fingerprint, name
        public event Action<string, string, string>? OnKeyChanged;       // key, oldFp, newFp

        public MessagingService(CryptoService crypto)
        {
            _crypto = crypto;
            ListenPort = int.TryParse(Environment.GetEnvironmentVariable("HLC_PORT"), out int p)
                ? p : DefaultPort;
            _listener = new TcpListener(IPAddress.Any, ListenPort);
        }

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
                        // Kết nối ĐẾN: chưa biết cổng lắng nghe của họ → chờ handshake mới có key
                        var peer = MakePeer(client);
                        _ = Task.Run(() => ReceiveLoopAsync(peer));
                        _ = Task.Run(() => SendHandshakeAsync(peer));
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[TCP accept] {ex.Message}");
                    }
                }
            });
        }

        public Task SendTextAsync(string key, string text)
            => SendFrameAsync(key, PacketType.Text, Encoding.UTF8.GetBytes(text));

        public async Task SendFrameAsync(string key, PacketType type, ReadOnlyMemory<byte> payload)
        {
            Peer peer = await GetOrConnectAsync(key);
            await peer.Ready.Task.WaitAsync(HandshakeTimeout, _cts.Token);

            byte[] encrypted = CryptoService.Encrypt(peer.SessionKey!, payload.Span);

            await peer.WriteLock.WaitAsync(_cts.Token);
            try
            {
                await Protocol.WriteFrameAsync(peer.Stream, type, encrypted, _cts.Token);
            }
            catch
            {
                RemovePeer(peer.Key);
                throw;
            }
            finally
            {
                peer.WriteLock.Release();
            }
        }

        /// <summary>Kết nối chủ động tới một endpoint. Trả về key "ip:port".</summary>
        public async Task<string> ConnectAsync(string host, int port)
        {
            string key = $"{host}:{port}";
            await GetOrConnectAsync(key);
            return key;
        }

        private async Task<Peer> GetOrConnectAsync(string key)
        {
            if (_peers.TryGetValue(key, out Peer? existing))
                return existing;

            int idx = key.LastIndexOf(':');
            if (idx < 0 || !int.TryParse(key[(idx + 1)..], out int port))
                throw new ArgumentException($"Endpoint không hợp lệ: {key}");
            string host = key[..idx];

            var client = new TcpClient();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await client.ConnectAsync(host, port, timeout.Token);

            // Kết nối ĐI: biết key ngay
            var peer = MakePeer(client);
            peer.Key = key;
            RegisterPeer(key, peer);
            OnPeerConnected?.Invoke(key);
            _ = Task.Run(() => ReceiveLoopAsync(peer));
            _ = Task.Run(() => SendHandshakeAsync(peer));
            return peer;
        }

        private Peer MakePeer(TcpClient client)
        {
            client.NoDelay = true;
            return new Peer { Client = client, Stream = client.GetStream() };
        }

        private void RegisterPeer(string key, Peer peer)
        {
            if (_peers.TryRemove(key, out Peer? old) && !ReferenceEquals(old, peer))
                old.Client.Close();
            _peers[key] = peer;
        }

        private async Task SendHandshakeAsync(Peer peer)
        {
            try
            {
                var msg = new HandshakeMsg(_crypto.PublicKey, peer.MySalt, Dns.GetHostName(), ListenPort);
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(msg);

                await peer.WriteLock.WaitAsync(_cts.Token);
                try
                {
                    await Protocol.WriteFrameAsync(peer.Stream, PacketType.Handshake, payload, _cts.Token);
                }
                finally { peer.WriteLock.Release(); }
            }
            catch { RemovePeer(peer.Key); }
        }

        private async Task ReceiveLoopAsync(Peer peer)
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var (type, payload) = await Protocol.ReadFrameAsync(peer.Stream, _cts.Token);

                    if (type == PacketType.Handshake)
                    {
                        HandleHandshake(peer, payload);
                        continue;
                    }

                    if (peer.SessionKey is null || peer.Key is null) continue;

                    byte[] plaintext = CryptoService.Decrypt(peer.SessionKey, payload);
                    switch (type)
                    {
                        case PacketType.Text:
                            OnTextReceived?.Invoke(peer.Key, Encoding.UTF8.GetString(plaintext));
                            break;
                        default:
                            OnFrameReceived?.Invoke(peer.Key, type, plaintext);
                            break;
                    }
                }
            }
            catch { /* stream đóng / gói giả mạo — fail-closed */ }
            finally
            {
                RemovePeer(peer.Key);
            }
        }

        private void HandleHandshake(Peer peer, byte[] payload)
        {
            var msg = JsonSerializer.Deserialize<HandshakeMsg>(payload)!;

            // Kết nối ĐẾN: giờ mới biết cổng lắng nghe thật của họ → chốt key
            if (peer.Key is null)
            {
                string ip = ((IPEndPoint)peer.Client.Client.RemoteEndPoint!).Address.ToString();
                peer.Key = $"{ip}:{msg.ListenPort}";
                RegisterPeer(peer.Key, peer);
                OnPeerConnected?.Invoke(peer.Key);
            }

            peer.SessionKey = _crypto.DeriveSessionKey(msg.PublicKey, peer.MySalt, msg.Salt);
            peer.Fingerprint = CryptoService.ComputeFingerprint(msg.PublicKey);
            peer.RemoteName = msg.Name;

            if (_seenFingerprints.TryGetValue(peer.Key, out string? known) && known != peer.Fingerprint)
                OnKeyChanged?.Invoke(peer.Key, known, peer.Fingerprint);
            _seenFingerprints[peer.Key] = peer.Fingerprint;

            peer.Ready.TrySetResult();
            OnPeerIdentified?.Invoke(peer.Key, peer.Fingerprint, peer.RemoteName);
        }

        private void RemovePeer(string? key)
        {
            if (key is null) return;
            if (_peers.TryRemove(key, out Peer? peer))
            {
                peer.Ready.TrySetCanceled();
                peer.Client.Close();
                OnPeerDisconnected?.Invoke(key);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            foreach (var key in _peers.Keys) RemovePeer(key);
            _cts.Dispose();
        }
    }
}