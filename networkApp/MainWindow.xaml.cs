using System.Windows;

namespace networkApp
{
    public partial class MainWindow : Window
    {
        private NetworkManager _network = new NetworkManager();

        public MainWindow()
        {
            InitializeComponent();
            txtIP.Text = _network.GetLocalIP();

            // BẮT ĐẦU LẮNG NGHE NGAY KHI MỞ APP
            _network.StartListeningForDiscovery();

            _network.OnDeviceFound += (ipFound) =>
            {
                Dispatcher.Invoke(() => {
                    if (!lstDevices.Items.Contains(ipFound))
                    {
                        lstDevices.Items.Add(ipFound);
                        txtStatus.Text = $"Đã thấy: {ipFound}";
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