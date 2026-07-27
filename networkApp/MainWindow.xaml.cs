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

        private readonly ObservableCollection<DeviceInfo> _devices = new();
        // Mọi thứ keyed theo endpoint "ip:port" (khớp với key của MessagingService)
        private readonly Dictionary<string, ObservableCollection<string>> _chatHistory = new();
        private readonly Dictionary<string, string> _verifiedLabels = new();
        private string? _activePeerKey;

        private static string F(string key, params object[] args)
            => string.Format(Localization.T(key), args);

        // Tạo DeviceInfo từ một endpoint key
        private static DeviceInfo DeviceFromKey(string key, string name)
        {
            int idx = key.LastIndexOf(':');
            string ip = idx >= 0 ? key[..idx] : key;
            return new DeviceInfo(ip, name) { Endpoint = key };
        }

        public MainWindow()
        {
            Localization.Initialize();
            InitializeComponent();

            _messaging = new MessagingService(_crypto);

            txtIP.Text = _discovery.LocalIP;
            txtFingerprint.Text = $"ID: {_crypto.Fingerprint}";
            // Hiện cổng đang lắng nghe (khác 8889 khi đặt HLC_PORT để loopback test)
            if (_messaging.ListenPort != MessagingService.DefaultPort)
                Title += $"  (port {_messaging.ListenPort})";
            lstDevices.ItemsSource = _devices;

            // ---------- Discovery (UDP) ----------
            _discovery.OnDeviceDiscovered += device => Dispatcher.Invoke(() =>
            {
                if (_devices.All(d => d.Endpoint != device.Endpoint))
                {
                    _devices.Add(device);
                    txtStatus.Text = F("L_Seen", device);
                }
            });
            _discovery.StartListening();

            // ---------- Messaging (TCP, mã hóa) — tham số 'key' là endpoint ----------
            _messaging.OnTextReceived += (key, text) => Dispatcher.Invoke(() =>
            {
                EnsureDevice(key, Localization.T("L_Unknown"));
                GetHistory(key).Add($"[{key}] {text}");
                ScrollChatToEnd(key);
            });

            _messaging.OnPeerConnected += key => Dispatcher.Invoke(() =>
                txtStatus.Text = F("L_TcpConnected", key));

            _messaging.OnPeerIdentified += (key, fingerprint, name) => Dispatcher.Invoke(() =>
            {
                _verifiedLabels[key] = $"{name} · {fingerprint}";
                EnsureDevice(key, name);
                txtStatus.Text = F("L_Verified", name, fingerprint);
                RefreshChatTitle();
            });

            _messaging.OnKeyChanged += (key, oldFp, newFp) => Dispatcher.Invoke(() =>
            {
                GetHistory(key).Add(F("L_KeyChangedChat", key, oldFp, newFp));
                MessageBox.Show(F("L_KeyChangedBody", key, oldFp, newFp),
                    Localization.T("L_KeyChangedTitle"),
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            });

            _messaging.OnPeerDisconnected += key => Dispatcher.Invoke(() =>
            {
                txtStatus.Text = F("L_TcpDisconnected", key);
                pnlProgress.Visibility = Visibility.Collapsed; // transfer dở dang → ẩn bar (fix đứng hình)
                if (key == _activePeerKey)
                    GetHistory(key).Add(Localization.T("L_ConnClosed"));
            });

            _messaging.StartListening();

            // ---------- File Transfer (consent-first + resume) ----------
            _files = new FileTransferService(_messaging);

            _files.OnIncomingOffer += (key, offer, resumeOffset) => Dispatcher.Invoke(async () =>
            {
                string senderLabel = _verifiedLabels.TryGetValue(key, out string? label) ? label : key;
                string mb = (offer.FileSize / 1024.0 / 1024.0).ToString("F1");
                string resumeNote = resumeOffset > 0
                    ? F("L_OfferResume", resumeOffset * 100 / Math.Max(offer.FileSize, 1))
                    : "";

                var choice = MessageBox.Show(
                    F("L_OfferBody", senderLabel, offer.FileName, mb, resumeNote),
                    Localization.T("L_OfferTitle"),
                    MessageBoxButton.YesNo, MessageBoxImage.Question);

                if (choice == MessageBoxResult.Yes)
                    await _files.AcceptAsync(key, offer);
                else
                    await _files.RejectAsync(key, offer);
            });

            _files.OnProgress += (name, done, total, sending) => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Visible;
                barTransfer.Value = total > 0 ? done * 100.0 / total : 0;
                string verb = Localization.T(sending ? "L_ProgSend" : "L_ProgRecv");
                txtTransfer.Text = $"{verb} {name}: {done / 1048576.0:F1}/{total / 1048576.0:F1} MB";
            });

            _files.OnCompleted += (nameOrPath, sending) => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Collapsed;
                if (_activePeerKey is not null)
                    GetHistory(_activePeerKey).Add(sending
                        ? F("L_SentDone", System.IO.Path.GetFileName(nameOrPath))
                        : F("L_RecvDone", nameOrPath));
                txtStatus.Text = Localization.T(sending ? "L_SentStatus" : "L_RecvStatus");
            });

            _files.OnFailed += (name, reason) => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Collapsed;
                txtStatus.Text = F("L_FileFail", name, reason);
            });

            _files.OnCanceled += name => Dispatcher.Invoke(() =>
            {
                pnlProgress.Visibility = Visibility.Collapsed;
                if (_activePeerKey is not null)
                    GetHistory(_activePeerKey).Add(F("L_Canceled", name));
                txtStatus.Text = F("L_Canceled", name);
            });
        }

        private async void btnCancelTransfer_Click(object sender, RoutedEventArgs e)
        {
            await _files.CancelAllAsync();
        }

        // =============== NGÔN NGỮ ===============

        private void btnLang_Click(object sender, RoutedEventArgs e)
        {
            Localization.Toggle();
            RefreshChatTitle();
        }

        private void RefreshChatTitle()
        {
            if (_activePeerKey is null) return;
            txtChatTitle.Text = _verifiedLabels.TryGetValue(_activePeerKey, out string? label)
                ? $"🔒 {label}"
                : F("L_ChatWith", _activePeerKey);
        }

        // =============== DISCOVERY UI ===============

        private async void btnScan_Click(object sender, RoutedEventArgs e)
        {
            btnScan.IsEnabled = false;
            txtStatus.Text = Localization.T("L_Scanning");
            _devices.Clear();
            try
            {
                await _discovery.ScanAsync();
                txtStatus.Text = _devices.Count > 0
                    ? F("L_ScanDone", _devices.Count)
                    : Localization.T("L_ScanNone");
            }
            catch (Exception ex) { txtStatus.Text = F("L_ScanError", ex.Message); }
            finally { btnScan.IsEnabled = true; }
        }

        // =============== KẾT NỐI THỦ CÔNG (loopback test / nhập IP tay) ===============

        private async void btnConnect_Click(object sender, RoutedEventArgs e)
        {
            string input = txtManual.Text.Trim();
            if (string.IsNullOrEmpty(input)) return;

            // Cho phép gõ "127.0.0.1:8890", "192.168.1.5", hoặc chỉ "8890" (→ 127.0.0.1:8890)
            string host; int port;
            if (input.Contains(':'))
            {
                int idx = input.LastIndexOf(':');
                host = input[..idx];
                if (!int.TryParse(input[(idx + 1)..], out port)) { txtStatus.Text = F("L_ConnectFail", input); return; }
            }
            else if (int.TryParse(input, out int p))
            {
                host = "127.0.0.1"; port = p;
            }
            else
            {
                host = input; port = MessagingService.DefaultPort;
            }

            txtManual.Clear();
            try
            {
                string key = await _messaging.ConnectAsync(host, port);
                EnsureDevice(key, Localization.T("L_ManualName"));
                SelectDevice(key);
            }
            catch (Exception ex) { txtStatus.Text = F("L_ConnectFail", ex.Message); }
        }

        // =============== CHAT UI ===============

        private void lstDevices_SelectionChanged(object sender, RoutedEventArgs e)
        {
            if (lstDevices.SelectedItem is DeviceInfo device)
                SelectDevice(device.Endpoint);
        }

        private void SelectDevice(string key)
        {
            _activePeerKey = key;
            RefreshChatTitle();
            lstMessages.ItemsSource = GetHistory(key);
            ScrollChatToEnd(key);
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
            if (_activePeerKey is null) { txtStatus.Text = Localization.T("L_SelectFirst"); return; }

            string target = _activePeerKey;
            txtInput.Clear();
            try
            {
                await _messaging.SendTextAsync(target, text);
                GetHistory(target).Add($"[{Localization.T("L_You")}] {text}");
                ScrollChatToEnd(target);
            }
            catch (Exception ex)
            {
                GetHistory(target).Add(F("L_SendFail", ex.Message));
                ScrollChatToEnd(target);
            }
        }

        private async void btnFile_Click(object sender, RoutedEventArgs e)
        {
            if (_activePeerKey is null) { txtStatus.Text = Localization.T("L_SelectFirst"); return; }

            var dialog = new Microsoft.Win32.OpenFileDialog { Title = Localization.T("L_ChooseFile") };
            if (dialog.ShowDialog() != true) return;

            string target = _activePeerKey;
            GetHistory(target).Add(F("L_Inviting", target, System.IO.Path.GetFileName(dialog.FileName)));
            await _files.SendFileAsync(target, dialog.FileName);
        }

        // =============== HELPERS ===============

        private void EnsureDevice(string key, string name)
        {
            var existing = _devices.FirstOrDefault(d => d.Endpoint == key);
            if (existing is null)
                _devices.Add(DeviceFromKey(key, name));
        }

        private ObservableCollection<string> GetHistory(string key)
        {
            if (!_chatHistory.TryGetValue(key, out var history))
            {
                history = new ObservableCollection<string>();
                _chatHistory[key] = history;
            }
            return history;
        }

        private void ScrollChatToEnd(string key)
        {
            if (key != _activePeerKey || lstMessages.Items.Count == 0) return;
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