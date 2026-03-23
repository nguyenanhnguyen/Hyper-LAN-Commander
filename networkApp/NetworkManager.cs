using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace networkApp
{
    public class NetworkManager
    {
        private const int DISCOVERY_PORT = 8888; // Cổng dùng chung để tìm kiếm
        private const string DISCOVERY_MESSAGE = "HYPER_LAN_SEARCH";

        public event Action<string> OnDeviceFound;

        // 1. Hàm lấy IP (Giữ nguyên hoặc cải tiến)
        public string GetLocalIP()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !ip.ToString().StartsWith("127."))
                    return ip.ToString();
            }
            return "127.0.0.1";
        }

        // 2. TÍNH NĂNG MỚI: Hét lên để tìm máy khác (Broadcast)
        public async Task StartScanning()
        {
            try
            {
                using (UdpClient udpClient = new UdpClient())
                {
                    udpClient.EnableBroadcast = true; // Cho phép gửi tin nhắn toàn mạng
                    byte[] data = Encoding.UTF8.GetBytes(DISCOVERY_MESSAGE);

                    // Gửi gói tin đến địa chỉ 255.255.255.255 (toàn bộ mạng LAN)
                    await udpClient.SendAsync(data, data.Length, new IPEndPoint(IPAddress.Broadcast, DISCOVERY_PORT));
                }

                // Sau khi hét xong, ta đợi 1 chút để nhận phản hồi (Logic nhận sẽ chạy ở luồng khác)
                await Task.Delay(1000);
            }
            catch (Exception ex) { /* Xử lý lỗi nếu cần */ }
        }

        // 3. TÍNH NĂNG MỚI: Lắng nghe xem có ai đang gọi mình không
        public void StartListeningForDiscovery()
        {
            Task.Run(async () =>
            {
                using (UdpClient listener = new UdpClient(DISCOVERY_PORT))
                {
                    while (true)
                    {
                        var result = await listener.ReceiveAsync();
                        string message = Encoding.UTF8.GetString(result.Buffer);

                        if (message == DISCOVERY_MESSAGE)
                        {
                            // Nếu thấy tin nhắn tìm kiếm, báo cho UI biết IP của máy đó
                            string senderIP = result.RemoteEndPoint.Address.ToString();

                            // Đừng hiện chính IP của mình
                            if (senderIP != GetLocalIP())
                            {
                                OnDeviceFound?.Invoke(senderIP);
                            }
                        }
                    }
                }
            });
        }
    }
}