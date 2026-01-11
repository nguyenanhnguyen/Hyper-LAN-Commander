using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace networkApp
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            // Gọi hàm hiển thị IP ngay khi khởi động
            DisplayLocalIP();
        }

        private void DisplayLocalIP()
        {
            try
            {
                // Lấy tên định danh máy tính
                string hostName = Dns.GetHostName();
                // Lấy danh sách địa chỉ IP
                IPAddress[] addresses = Dns.GetHostAddresses(hostName);

                foreach (IPAddress ip in addresses)
                {
                    // Chỉ lọc IPv4
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        // Cập nhật lên giao diện thay vì hiện MessageBox
                        txtIP.Text = ip.ToString();
                        txtStatus.Text = "Trạng thái: Đã nhận diện IP nội bộ";
                        return; // Thoát hàm khi tìm thấy IP đầu tiên
                    }
                }
            }
            catch (Exception ex)
            {
                // Chỉ dùng MessageBox khi có lỗi nghiêm trọng
                MessageBox.Show("Lỗi lấy IP: " + ex.Message);
            }
        }
    }
}