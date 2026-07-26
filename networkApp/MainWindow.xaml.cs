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
        private readonly CryptoService _crypto = new();
        private readonly DiscoveryService _discovery = new();
        private readonly MessagingService _messaging;
        private readonly FileTransferService _files;

        // Tên + fingerprint đã xác thực của từng IP (từ handshake ECDH)
        private readonly Dictionary<string, string> _verifiedLabels = new();

        private readonly ObservableCollection<DeviceInfo> _devices = new();

        // Lịch sử chat tách theo từng IP — đổi thiết bị vẫn giữ nguyên hội thoại
        private readonly Dictionary<string, ObservableCollection<string>> _chatHistory = new();
        private string? _activePeerIP;

        public MainWindow()
        {
            InitializeComponent();

            _messaging = new MessagingService(_crypto);

            txtIP.Text = _discovery.LocalIP;
            txtFingerprint.Text = $"ID: {_crypto.Fingerprint}";
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

            _messaging.OnPeerIdentified += (ip, fingerprint, name) => Dispatcher.Invoke(() =>
            {
                _verifiedLabels[ip] = $"{name} · {fingerprint}";
                txtStatus.Text = $"Đã xác thực: {name} ({fingerprint})";
                if (ip == _activePeerIP)
                    txtChatTitle.Text = $"🔒 {name} · {fingerprint}";
            });

            _messaging.OnKeyChanged += (ip, oldFp, newFp) => Dispatcher.Invoke(() =>
            {
                GetHistory(ip).Add($"⚠ CẢNH BÁO: danh tính tại {ip} đã THAY ĐỔI ({oldFp} → {newFp})!");
                MessageBox.Show(
                    $"Danh tính mật mã tại {ip} đã THAY ĐỔI!\n\n" +
                    $"Trước: {oldFp}\nNay:   {newFp}\n\n" +
                    "Có thể máy đó cài lại app... hoặc một máy KHÁC đang chiếm IP này.\n" +
                    "Hãy xác nhận với người bên kia (đọc ID cho nhau) trước khi gửi thông tin nhạy cảm.",
                    "Cảnh báo an ninh", MessageBoxButton.OK, MessageBoxImage.Warning);
            });

            _messaging.OnPeerDisconnected += ip => Dispatcher.Invoke(() =>
            {
                txtStatus.Text = $"TCP: {ip} đã ngắt";
                if (ip == _activePeerIP)
                    GetHistory(ip).Add("— Kết nối đã đóng —");
            });

            _messaging.StartListening();

            // ---------- File Transfer (consent-first + resume) ----------
            _files = new FileTransferService(_messaging);

            _files.OnIncomingOffer += (ip, offer, resumeOffset) => Dispatcher.Invoke(async () =>
            {
                double mb = offer.FileSize / 1024.0 / 1024.0;
                string resumeNote = resumeOffset > 0
                    ? $"\n(Đã có {resumeOffset * 100 / Math.Max(offer.FileSize, 1)}% từ lần trước — sẽ tải tiếp)"
                    : "";
                var choice = MessageBox.Show(
                    $"{ip} muốn gửi file:\n\n{offer.FileName}  ({mb:F1} MB){resumeNote}\n\nNhận file này?",
                    "Yêu cầu gửi file", MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (choice == MessageBoxResult.Yes)
                    await _files.AcceptAsync(ip, offer);
                else
                    await _files.RejectAsync(ip, offer);
            });

            _files.OnProgress += (name, done, total, sending) => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Visible;
                barTransfer.Value = total > 0 ? done * 100.0 / total : 0;
                txtTransfer.Text = $"{(sending ? "Gửi" : "Nhận")} {name}: {done / 1048576.0:F1}/{total / 1048576.0:F1} MB";
            });

            _files.OnCompleted += (nameOrPath, sending) => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Collapsed;
                if (_activePeerIP is not null)
                    GetHistory(_activePeerIP).Add(sending
                        ? $"— Đã gửi xong: {System.IO.Path.GetFileName(nameOrPath)} —"
                        : $"— Đã nhận file: {nameOrPath} —");
                txtStatus.Text = sending ? "Gửi file hoàn tất" : "Nhận file hoàn tất";
            });

            _files.OnFailed += (name, reason) => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Collapsed;
                txtStatus.Text = $"File {name}: {reason}";
            });
        }

        private async void btnFile_Click(object sender, RoutedEventArgs e)
        {
            if (_activePeerIP is null)
            {
                txtStatus.Text = "Hãy chọn một thiết bị trước";
                return;
            }

            var dialog = new Microsoft.Win32.OpenFileDialog { Title = "Chọn file để gửi" };
            if (dialog.ShowDialog() != true) return;

            string target = _activePeerIP;
            GetHistory(target).Add($"— Đang mời {target} nhận file {System.IO.Path.GetFileName(dialog.FileName)}... —");
            await _files.SendFileAsync(target, dialog.FileName);
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
            txtChatTitle.Text = _verifiedLabels.TryGetValue(device.IpAddress, out string? label)
                ? $"🔒 {label}"
                : $"Chat với {device}";
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
            _files.Dispose();
            _discovery.Dispose();
            _messaging.Dispose();
            base.OnClosed(e);
        }
    }
}
