using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace networkApp
{
    public class NetworkManager
    {
        // Sự kiện: Khi tìm thấy 1 IP mới, nó sẽ "hét" lên để MainWindow nghe thấy
        public event Action<string> OnDeviceFound;

        // Hàm lấy IP của máy hiện tại
        public string GetLocalIP()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork) return ip.ToString();
            }
            return "127.0.0.1";
        }

        // Hàm giả lập việc quét mạng (Sau này sẽ thay bằng code UDP thực tế)
        public async Task StartScanning()
        {
            // Giả sử sau 2 giây tìm thấy một máy ảo VirtualBox
            await Task.Delay(2000);
            OnDeviceFound?.Invoke("192.168.56.101 (Virtual Machine)");
        }
    }
}