using System.Windows;

namespace networkApp
{
    public partial class MainWindow : Window
    {
        private NetworkManager _network = new NetworkManager();

        public MainWindow()
        {
            InitializeComponent();

            // Lấy IP hiển thị ngay
            txtIP.Text = _network.GetLocalIP();

            // Đăng ký sự kiện khi tìm thấy thiết bị
            _network.OnDeviceFound += (ipFound) =>
            {
                Dispatcher.Invoke(() => {
                    if (!lstDevices.Items.Contains(ipFound))
                    {
                        lstDevices.Items.Add(ipFound);
                        txtStatus.Text = "Trạng thái: Đã tìm thấy máy mới!";
                    }
                });
            };
        }

        private async void btnScan_Click(object sender, RoutedEventArgs e)
        {
            txtStatus.Text = "Trạng thái: Đang quét...";
            btnScan.IsEnabled = false;

            await _network.StartScanning();

            btnScan.IsEnabled = true;
            txtStatus.Text = "Trạng thái: Quét hoàn tất";
        }
    }
}