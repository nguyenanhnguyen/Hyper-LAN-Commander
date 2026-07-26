using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace networkApp
{
    public partial class MainWindow : Window
    {
        private readonly DiscoveryService _discovery = new();
        private readonly MessagingService _messaging = new();

        private readonly ObservableCollection<DeviceInfo> _devices = new();

        // Lịch sử chat tách theo từng IP — đổi thiết bị vẫn giữ nguyên hội thoại
        private readonly Dictionary<string, ObservableCollection<string>> _chatHistory = new();
        private string? _activePeerIP;

        public MainWindow()
        {
            InitializeComponent();

            txtIP.Text = _discovery.LocalIP;
            lstDevices.ItemsSource = _devices;

            // ---------- Discovery (UDP) ----------
            _discovery.OnDeviceDiscovered += device => Dispatcher.Invoke(() =>
            {
                if (_devices.All(d => d.IpAddress != device.IpAddress))
                {
                    _devices.Add(device);
                    txtStatus.Text = $"Đã thấy: {device}";
                }
            });
            _discovery.StartListening();

            // ---------- Messaging (TCP) ----------
            _messaging.OnTextReceived += (ip, text) => Dispatcher.Invoke(() =>
            {
                GetHistory(ip).Add($"[{ip}] {text}");
                // Nếu người gửi chưa có trong list thiết bị (chưa quét) thì vẫn hiện họ lên
                if (_devices.All(d => d.IpAddress != ip))
                    _devices.Add(new DeviceInfo(ip, "(chưa rõ tên)"));
                ScrollChatToEnd(ip);
            });

            _messaging.OnPeerConnected += ip => Dispatcher.Invoke(() =>
                txtStatus.Text = $"TCP: {ip} đã kết nối");

            _messaging.OnPeerDisconnected += ip => Dispatcher.Invoke(() =>
            {
                txtStatus.Text = $"TCP: {ip} đã ngắt";
                if (ip == _activePeerIP)
                    GetHistory(ip).Add("— Kết nối đã đóng —");
            });

            _messaging.StartListening();
        }

        // =============== DISCOVERY UI ===============

        private async void btnScan_Click(object sender, RoutedEventArgs e)
        {
            btnScan.IsEnabled = false;
            txtStatus.Text = "Trạng thái: Đang quét...";
            _devices.Clear();
            try
            {
                await _discovery.ScanAsync();
                txtStatus.Text = _devices.Count > 0
                    ? $"Quét xong: {_devices.Count} thiết bị"
                    : "Quét xong: không thấy thiết bị nào";
            }
            catch (Exception ex) { txtStatus.Text = $"Lỗi quét: {ex.Message}"; }
            finally { btnScan.IsEnabled = true; }
        }

        // =============== CHAT UI ===============

        private void lstDevices_SelectionChanged(object sender, RoutedEventArgs e)
        {
            if (lstDevices.SelectedItem is not DeviceInfo device) return;

            _activePeerIP = device.IpAddress;
            txtChatTitle.Text = $"Chat với {device}";
            lstMessages.ItemsSource = GetHistory(device.IpAddress);
            ScrollChatToEnd(device.IpAddress);
            txtInput.Focus();
        }

        private async void btnSend_Click(object sender, RoutedEventArgs e) => await SendCurrentAsync();

        private async void txtInput_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) await SendCurrentAsync();
        }

        private async System.Threading.Tasks.Task SendCurrentAsync()
        {
            string text = txtInput.Text.Trim();
            if (string.IsNullOrEmpty(text)) return;

            if (_activePeerIP is null)
            {
                txtStatus.Text = "Hãy chọn một thiết bị trước";
                return;
            }

            string target = _activePeerIP;
            txtInput.Clear();
            try
            {
                await _messaging.SendTextAsync(target, text);
                GetHistory(target).Add($"[Bạn] {text}");
                ScrollChatToEnd(target);
            }
            catch (Exception ex)
            {
                GetHistory(target).Add($"— Gửi thất bại: {ex.Message} —");
                ScrollChatToEnd(target);
            }
        }

        private ObservableCollection<string> GetHistory(string ip)
        {
            if (!_chatHistory.TryGetValue(ip, out var history))
            {
                history = new ObservableCollection<string>();
                _chatHistory[ip] = history;
            }
            return history;
        }

        private void ScrollChatToEnd(string ip)
        {
            if (ip != _activePeerIP || lstMessages.Items.Count == 0) return;
            lstMessages.ScrollIntoView(lstMessages.Items[^1]);
        }

        protected override void OnClosed(EventArgs e)
        {
            _discovery.Dispose();
            _messaging.Dispose();
            base.OnClosed(e);
        }
    }
}