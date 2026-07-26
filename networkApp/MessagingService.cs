using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>
    /// TCP messaging đa kết nối (mỗi peer một TcpClient, mỗi kết nối một
    /// receive-loop chạy nền — mô hình worker per connection).
    ///
    /// Điểm học thuật để trình bày:
    /// - TCP three-way handshake xảy ra bên trong ConnectAsync/AcceptTcpClientAsync.
    /// - Flow control / sliding window do TCP tự lo; tầng app chỉ cần framing (Protocol.cs).
    /// - SemaphoreSlim mỗi kết nối: 2 luồng cùng ghi 1 stream sẽ trộn lẫn byte → phải khóa.
    /// </summary>
    public class MessagingService : IDisposable
    {
        public const int Port = 8889;

        private sealed class Peer
        {
            public required TcpClient Client { get; init; }
            public required NetworkStream Stream { get; init; }
            public SemaphoreSlim WriteLock { get; } = new(1, 1);
        }

        private readonly TcpListener _listener = new(IPAddress.Any, Port);
        private readonly ConcurrentDictionary<string, Peer> _peers = new();
        private readonly CancellationTokenSource _cts = new();

        /// <summary>(ip, nội dung) — tin nhắn đến từ peer.</summary>
        public event Action<string, string>? OnTextReceived;
        /// <summary>ip — peer vừa kết nối tới mình (inbound).</summary>
        public event Action<string>? OnPeerConnected;
        /// <summary>ip — kết nối đã đóng.</summary>
        public event Action<string>? OnPeerDisconnected;

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

        /// <summary>Gửi text tới peer; tự mở kết nối nếu chưa có (lazy connect).</summary>
        public async Task SendTextAsync(string ip, string text)
        {
            Peer peer = await GetOrConnectAsync(ip);
            await peer.WriteLock.WaitAsync(_cts.Token);
            try
            {
                await Protocol.WriteTextAsync(peer.Stream, text, _cts.Token);
            }
            catch
            {
                RemovePeer(ip);   // gửi hỏng = kết nối chết → dọn để lần sau reconnect
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
            // Timeout 3s: không để UI treo vô hạn khi peer đã tắt app
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(3));
            await client.ConnectAsync(IPAddress.Parse(ip), Port, timeout.Token);

            return AddPeer(ip, client);
        }

        private Peer AddPeer(string ip, TcpClient client)
        {
            client.NoDelay = true; // tắt Nagle — chat cần độ trễ thấp hơn là gom gói
            var peer = new Peer { Client = client, Stream = client.GetStream() };

            // Nếu đã có kết nối cũ (2 bên connect chéo nhau cùng lúc) → giữ cái mới
            if (_peers.TryRemove(ip, out Peer? old))
                old.Client.Close();
            _peers[ip] = peer;

            _ = Task.Run(() => ReceiveLoopAsync(ip, peer)); // worker riêng cho kết nối này
            return peer;
        }

        private async Task ReceiveLoopAsync(string ip, Peer peer)
        {
            try
            {
                while (!_cts.IsCancellationRequested)
                {
                    var (type, payload) = await Protocol.ReadFrameAsync(peer.Stream, _cts.Token);
                    switch (type)
                    {
                        case PacketType.Text:
                            OnTextReceived?.Invoke(ip, Encoding.UTF8.GetString(payload));
                            break;
                        // Các PacketType file sẽ xử lý ở tuần File Transfer
                        default:
                            System.Diagnostics.Debug.WriteLine($"[TCP] Gói chưa hỗ trợ: {type}");
                            break;
                    }
                }
            }
            catch { /* EndOfStream / socket đóng — rơi xuống cleanup */ }
            finally
            {
                RemovePeer(ip);
            }
        }

        private void RemovePeer(string ip)
        {
            if (_peers.TryRemove(ip, out Peer? peer))
            {
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
