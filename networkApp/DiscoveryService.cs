using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>
    /// Thông tin một thiết bị được phát hiện trong LAN.
    /// </summary>
    public record DeviceInfo(string IpAddress, string HostName)
    {
        public DateTime LastSeen { get; set; } = DateTime.Now;
        public override string ToString() => $"{HostName}  ({IpAddress})";
    }

    /// <summary>
    /// Zero-configuration discovery bằng UDP Broadcast — handshake 2 chiều:
    ///
    ///   Máy A ──[DISCOVER broadcast 255.255.255.255:8888]──▶ toàn mạng
    ///   Máy B ──[REPLY unicast về đúng IP:port của A]──────▶ Máy A
    ///
    /// Nhờ REPLY unicast, máy chủ động quét cũng thấy được các máy khác
    /// (bản 1 chiều cũ chỉ có máy "ngồi im" mới thấy máy đi quét).
    /// </summary>
    public class DiscoveryService : IDisposable
    {
        private const int DiscoveryPort = 8888;
        private const string ProtocolId = "HLC1";           // đổi version protocol thì tăng số này
        private const string MsgDiscover = ProtocolId + "|DISCOVER|";
        private const string MsgReply    = ProtocolId + "|REPLY|";

        private readonly UdpClient _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly HashSet<string> _localIPs;

        /// <summary>Bắn lên UI khi phát hiện thiết bị mới hoặc thiết bị cũ "ping" lại.</summary>
        public event Action<DeviceInfo>? OnDeviceDiscovered;

        public string LocalIP { get; }
        public string LocalHostName { get; }

        public DiscoveryService()
        {
            LocalHostName = Dns.GetHostName();
            LocalIP = ResolveLocalIP();
            _localIPs = GetAllLocalIPs();

            // ReuseAddress: cho phép chạy 2 instance trên cùng 1 máy để test,
            // và tránh SocketException khi app khởi động lại nhanh (port TIME_WAIT).
            _listener = new UdpClient();
            _listener.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            _listener.Client.Bind(new IPEndPoint(IPAddress.Any, DiscoveryPort));
        }

        /// <summary>
        /// Chạy vòng lặp lắng nghe ở background. Xử lý CẢ 2 loại gói:
        /// - DISCOVER  → có người đang quét → trả lời REPLY unicast về cho họ.
        /// - REPLY     → phản hồi cho lượt quét của chính mình → báo UI.
        /// </summary>
        public void StartListening()
        {
            _ = Task.Run(async () =>
            {
                while (!_cts.IsCancellationRequested)
                {
                    try
                    {
                        UdpReceiveResult result = await _listener.ReceiveAsync(_cts.Token);
                        string senderIP = result.RemoteEndPoint.Address.ToString();

                        // Bỏ qua gói do chính mình broadcast (loopback trên mọi card mạng)
                        if (_localIPs.Contains(senderIP)) continue;

                        string message = Encoding.UTF8.GetString(result.Buffer);

                        if (message.StartsWith(MsgDiscover))
                        {
                            // Có máy đang tìm mình → chào lại đúng địa chỉ của nó (unicast)
                            string hostName = message[MsgDiscover.Length..];
                            RaiseFound(senderIP, hostName);

                            byte[] reply = Encoding.UTF8.GetBytes(MsgReply + LocalHostName);
                            await _listener.SendAsync(reply, reply.Length, result.RemoteEndPoint);
                        }
                        else if (message.StartsWith(MsgReply))
                        {
                            // Máy khác trả lời lượt quét của mình
                            string hostName = message[MsgReply.Length..];
                            RaiseFound(senderIP, hostName);
                        }
                        // Gói lạ (không đúng ProtocolId) → lặng lẽ bỏ qua, không crash
                    }
                    catch (OperationCanceledException) { break; }          // app đang đóng
                    catch (SocketException) { /* mạng chớp nhoáng, thử vòng sau */ }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine($"[Discovery] {ex.Message}");
                    }
                }
            });
        }

        /// <summary>
        /// Broadcast gói DISCOVER tới toàn bộ subnet. REPLY sẽ quay về
        /// listener ở trên (cùng socket → cùng port → NAT/firewall thân thiện).
        /// Gửi 3 lần cách nhau 300ms vì UDP không đảm bảo tới nơi.
        /// </summary>
        public async Task ScanAsync()
        {
            byte[] data = Encoding.UTF8.GetBytes(MsgDiscover + LocalHostName);
            var broadcastEP = new IPEndPoint(IPAddress.Broadcast, DiscoveryPort);

            _listener.EnableBroadcast = true;
            for (int i = 0; i < 3 && !_cts.IsCancellationRequested; i++)
            {
                await _listener.SendAsync(data, data.Length, broadcastEP);
                await Task.Delay(300, _cts.Token).ConfigureAwait(false);
            }
        }

        private void RaiseFound(string ip, string hostName)
            => OnDeviceDiscovered?.Invoke(new DeviceInfo(ip, hostName));

        /// <summary>
        /// Lấy IP "outbound" thật của máy: mở UDP socket ảo tới 8.8.8.8 rồi đọc
        /// LocalEndPoint. Không gửi gói nào đi cả — chỉ để OS chọn đúng card mạng.
        /// Chính xác hơn Dns.GetHostEntry khi máy có VPN/Hyper-V/nhiều adapter.
        /// </summary>
        private static string ResolveLocalIP()
        {
            try
            {
                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.Connect("8.8.8.8", 65530);
                return ((IPEndPoint)socket.LocalEndPoint!).Address.ToString();
            }
            catch
            {
                return "127.0.0.1"; // máy không có mạng
            }
        }

        private static HashSet<string> GetAllLocalIPs()
        {
            var ips = new HashSet<string> { "127.0.0.1" };
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var addr in ni.GetIPProperties().UnicastAddresses)
                    if (addr.Address.AddressFamily == AddressFamily.InterNetwork)
                        ips.Add(addr.Address.ToString());
            return ips;
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Close();
            _cts.Dispose();
        }
    }
}
