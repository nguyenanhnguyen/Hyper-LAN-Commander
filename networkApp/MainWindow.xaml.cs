using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Threading;

namespace networkApp
{
    /// <summary>
    /// Cửa sổ chính = lớp điều phối mỏng: nối sự kiện của các service (chạy trên thread nền)
    /// vào ViewModel (chạy trên UI thread qua Dispatcher.BeginInvoke — KHÔNG BAO GIỜ chặn
    /// luồng mạng chờ UI như bản cũ dùng Dispatcher.Invoke + MessageBox).
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly AppProfile _profile;
        private readonly CryptoService _crypto;
        private readonly TrustStore _trust;
        private readonly MessagingService _messaging;
        private readonly FileTransferService _files;
        private readonly DiscoveryService _discovery;

        private readonly ObservableCollection<PeerViewModel> _peers = new();
        private readonly Dictionary<string, PeerViewModel> _peerByFp = new();
        private readonly Dictionary<string, ObservableCollection<ChatItem>> _history = new();
        private readonly Dictionary<Guid, TransferViewModel> _transfers = new();
        private PeerViewModel? _active;

        private readonly DispatcherTimer _statsTimer;
        private long _lastSent, _lastRecv;
        private DateTime _lastStatsAt = DateTime.UtcNow;

        public MainWindow()
        {
            Localization.Initialize();
            InitializeComponent();

            _profile = AppProfile.Acquire();
            _crypto = new CryptoService(_profile.DataDir);
            _trust = new TrustStore(_profile.DataDir);

            _messaging = new MessagingService(_crypto, _profile.DisplayName, _profile.PreferredTcpPort);
            _files = new FileTransferService(_messaging, _profile.DownloadDir);
            WireMessaging();
            WireFiles();
            _messaging.Start();

            // Discovery cần cổng TCP THẬT (có thể khác 8889 nếu cổng đã bị chiếm)
            _discovery = new DiscoveryService(_messaging.InstanceId, _crypto.Fingerprint,
                                              _profile.DisplayName, _messaging.ListenPort);
            WireDiscovery();
            _discovery.Start();

            var view = (ListCollectionView)CollectionViewSource.GetDefaultView(_peers);
            view.SortDescriptions.Add(new SortDescription(nameof(PeerViewModel.SortKey), ListSortDirection.Ascending));
            view.IsLiveSorting = true;
            view.LiveSortingProperties.Add(nameof(PeerViewModel.SortKey));
            lstPeers.ItemsSource = view;

            LoadKnownPeers();
            UpdateIdentityCard();
            UpdatePeerCount();

            if (!_profile.IsDefault) Title += $"  —  profile #{_profile.Name}";

            _statsTimer = new DispatcherTimer(TimeSpan.FromSeconds(1), DispatcherPriority.Background,
                (_, _) => UpdateNetStats(), Dispatcher);
            _statsTimer.Start();
            UpdateNetStats();
        }

        private void Ui(Action a) => Dispatcher.BeginInvoke(a);

        // =====================================================================
        //  NỐI SỰ KIỆN
        // =====================================================================

        private void WireDiscovery()
        {
            _discovery.PeerSeen += p =>
            {
                _messaging.AddEndpoint(p.Fingerprint, p.TcpEndPoint); // thread-safe, làm ngay
                Ui(() =>
                {
                    bool wasKnown = _peerByFp.TryGetValue(p.Fingerprint, out var existing) && existing.IsOnline;
                    var vm = GetPeer(p.Fingerprint, p.Name);
                    if (!vm.IsConnected) vm.Name = p.Name;
                    vm.Endpoint = p.TcpEndPoint.ToString();
                    vm.IsDiscovered = true;
                    if (!wasKnown) SetStatus(Fmt.F("L_Seen", p.Name));
                    UpdatePeerCount();
                    if (vm == _active) RefreshHeader();
                });
            };

            _discovery.PeerLost += p => Ui(() =>
            {
                if (!_peerByFp.TryGetValue(p.Fingerprint, out var vm)) return;
                vm.IsDiscovered = false;
                if (!vm.IsConnected) SetStatus(Fmt.F("L_PeerLeft", vm.Name));
                UpdatePeerCount();
                if (vm == _active) RefreshHeader();
            });

            _discovery.NetworkChanged += () => Ui(() =>
            {
                UpdateIdentityCard();
                SetStatus(Localization.T("L_NetChanged"));
            });
        }

        private void WireMessaging()
        {
            _messaging.SessionEstablished += info => Ui(() => OnSessionEstablished(info));

            _messaging.SessionLost += (fp, reason) => Ui(() =>
            {
                if (!_peerByFp.TryGetValue(fp, out var vm)) return;
                vm.IsConnected = false;
                if (reason == CloseReason.Tampered)
                    AddChat(fp, new ChatItem { Kind = ChatKind.Warning, Text = Localization.T("L_TamperedChat") });
                if (reason != CloseReason.Shutdown) SetStatus(Fmt.F("L_SessionLost", vm.Name));
                UpdatePeerCount();
                if (vm == _active) RefreshHeader();
            });

            _messaging.RttUpdated += (fp, ms) => Ui(() =>
            {
                if (!_peerByFp.TryGetValue(fp, out var vm)) return;
                vm.RttMs = ms;
                if (vm == _active) RefreshRtt();
            });

            _messaging.TextReceived += (fp, text) => Ui(() =>
            {
                var vm = GetPeer(fp, Localization.T("L_Unknown"));
                AddChat(fp, new ChatItem { Kind = ChatKind.Theirs, Text = text });
                if (vm != _active) vm.Unread++;
                FlashIfInactive();
            });

            _messaging.ConnectionRejected += (endpoint, reason, _) => Ui(() =>
            {
                if (reason == CloseReason.SelfConnection) return; // đã báo ở nút Kết nối
                string why = reason switch
                {
                    CloseReason.Tampered => "AES-GCM tag mismatch",
                    CloseReason.AuthFailed => "ECDSA signature invalid",
                    CloseReason.ProtocolError => "protocol violation",
                    _ => reason.ToString(),
                };
                SetStatus(Fmt.F("L_Rejected", endpoint, why));
            });
        }

        private void OnSessionEstablished(PeerSessionInfo info)
        {
            var vm = GetPeer(info.Fingerprint, info.Name);
            vm.Name = info.Name;
            vm.IsConnected = true;
            vm.PublicKey = info.PublicKey;
            vm.SessionId = info.SessionId;
            if (!vm.IsDiscovered || string.IsNullOrEmpty(vm.Endpoint))
                vm.Endpoint = info.ListenEndPoint.ToString();

            // TOFU: ghi nhận danh tính đã XÁC THỰC; cảnh báo nếu tên quen nay mang khóa lạ
            var obs = _trust.Observe(info.Fingerprint, info.Name, info.PublicKey,
                                     info.RemoteEndPoint.Address.ToString(), info.ListenPort);
            vm.IsVerified = obs.Peer.Verified;
            vm.IsNew = obs.IsNew;
            vm.LastSeen = DateTime.Now;

            if (obs.Conflict is { } old)
            {
                AddChat(info.Fingerprint, new ChatItem
                {
                    Kind = ChatKind.Warning,
                    Text = Fmt.F("L_KeyChangedChat", info.Name, old.Fingerprint, info.Fingerprint),
                });
                if (_peerByFp.TryGetValue(old.Fingerprint, out var oldVm) && !oldVm.IsOnline)
                    RemovePeer(oldVm);
                MessageBox.Show(this,
                    Fmt.F("L_KeyChangedBody", info.Name, old.Fingerprint, info.Fingerprint,
                          old.Verified ? Localization.T("L_WasVerified") : ""),
                    Localization.T("L_KeyChangedTitle"), MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            else if (obs.IsNew)
            {
                AddChat(info.Fingerprint, new ChatItem { Kind = ChatKind.System, Text = Localization.T("L_NewIdentity") });
            }

            SetStatus(Fmt.F("L_Verified", info.Name, info.Fingerprint));
            UpdatePeerCount();
            if (vm == _active) RefreshHeader();
        }

        private void WireFiles()
        {
            _files.Updated += snap => Ui(() =>
            {
                if (!_transfers.TryGetValue(snap.Id, out var vm))
                {
                    var peer = GetPeer(snap.PeerFingerprint, Localization.T("L_Unknown"));
                    vm = new TransferViewModel(snap, peer.Name);
                    _transfers[snap.Id] = vm;
                    AddChat(snap.PeerFingerprint, new ChatItem { Kind = ChatKind.Transfer, Transfer = vm });

                    if (snap.State == TransferState.AwaitingDecision)
                    {
                        SetStatus(Fmt.F("L_IncomingFile", peer.Name, snap.FileName));
                        if (peer != _active) peer.Unread++;
                        FlashIfInactive();
                    }
                }
                else
                {
                    vm.Apply(snap);
                }

                if (snap.State == TransferState.Completed)
                    SetStatus(Fmt.F(snap.Direction == TransferDirection.Send ? "L_SentStatus" : "L_RecvStatus", snap.FileName));
            });
        }

        // =====================================================================
        //  PEER & LỊCH SỬ
        // =====================================================================

        private PeerViewModel GetPeer(string fp, string name)
        {
            if (_peerByFp.TryGetValue(fp, out var vm)) return vm;
            vm = new PeerViewModel(fp, name);
            _peerByFp[fp] = vm;
            _peers.Add(vm);
            txtNoPeers.Visibility = Visibility.Collapsed;
            return vm;
        }

        private void RemovePeer(PeerViewModel vm)
        {
            if (vm == _active) return;
            _peers.Remove(vm);
            _peerByFp.Remove(vm.Fingerprint);
            txtNoPeers.Visibility = _peers.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        /// <summary>Hiện các peer đã từng gặp (offline) — gửi tin là tự thử kết nối địa chỉ cũ.</summary>
        private void LoadKnownPeers()
        {
            foreach (var k in _trust.Recent(TimeSpan.FromDays(30)))
            {
                var vm = GetPeer(k.Fingerprint, k.Name);
                vm.IsVerified = k.Verified;
                vm.PublicKey = k.PublicKey;
                vm.LastSeen = k.LastSeen;
                if (k.LastAddress is not null && IPAddress.TryParse(k.LastAddress, out var ip) && k.LastPort > 0)
                {
                    var ep = new IPEndPoint(ip, k.LastPort);
                    vm.Endpoint = ep.ToString();
                    _messaging.AddEndpoint(k.Fingerprint, ep);
                }
            }
        }

        private ObservableCollection<ChatItem> History(string fp)
        {
            if (!_history.TryGetValue(fp, out var h))
            {
                h = new ObservableCollection<ChatItem>();
                _history[fp] = h;
            }
            return h;
        }

        private void AddChat(string fp, ChatItem item)
        {
            var h = History(fp);
            h.Add(item);
            if (h.Count > 2000) h.RemoveAt(0); // giữ RAM ổn định khi chat rất dài
            if (_active?.Fingerprint == fp) ScrollToEnd();
        }

        private void ScrollToEnd()
        {
            if (lstMessages.Items.Count == 0) return;
            Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                if (lstMessages.Items.Count > 0) lstMessages.ScrollIntoView(lstMessages.Items[^1]);
            });
        }

        // =====================================================================
        //  CHỌN PEER / HEADER
        // =====================================================================

        private void lstPeers_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (lstPeers.SelectedItem is PeerViewModel vm) SelectPeer(vm);
        }

        private void SelectPeer(PeerViewModel vm)
        {
            _active = vm;
            vm.Unread = 0;
            if (!Equals(lstPeers.SelectedItem, vm)) lstPeers.SelectedItem = vm;
            lstMessages.ItemsSource = History(vm.Fingerprint);
            pnlEmpty.Visibility = Visibility.Collapsed;
            pnlHeader.Visibility = Visibility.Visible;
            pnlInput.IsEnabled = true;
            pnlSafety.Visibility = Visibility.Collapsed;
            RefreshHeader();
            ScrollToEnd();
            txtInput.Focus();
        }

        private void RefreshHeader()
        {
            if (_active is not { } p) return;
            txtChatTitle.Text = p.Name;
            txtAvatar.Text = p.Initials;
            txtPeerFp.Text = $"ID {p.Fingerprint}" + (string.IsNullOrEmpty(p.Endpoint) ? "" : $"  ·  {p.Endpoint}");
            txtChatSub.Text = p.IsConnected
                ? Fmt.F("L_SecureSub", p.SessionId ?? "-")
                : Localization.T(p.IsDiscovered ? "L_OnlineSub" : "L_OfflineSub");
            txtChatSub.Foreground = (System.Windows.Media.Brush)FindResource(p.IsConnected ? "SuccessText" : "Muted");
            badgeVerified.Visibility = p.IsVerified ? Visibility.Visible : Visibility.Collapsed;
            RefreshRtt();
            if (pnlSafety.Visibility == Visibility.Visible) RefreshSafety();
        }

        private void RefreshRtt()
        {
            if (_active is not { } p) return;
            badgeRtt.Visibility = p.HasRtt ? Visibility.Visible : Visibility.Collapsed;
            txtRtt.Text = $"RTT {p.RttText}";
        }

        private void btnSafety_Click(object sender, RoutedEventArgs e)
        {
            pnlSafety.Visibility = pnlSafety.Visibility == Visibility.Visible ? Visibility.Collapsed : Visibility.Visible;
            if (pnlSafety.Visibility == Visibility.Visible) RefreshSafety();
        }

        private void RefreshSafety()
        {
            if (_active is not { } p) return;
            if (p.PublicKey is null)
            {
                txtSafety.Text = Localization.T("L_SafetyNone");
                txtSafety.FontSize = 13;
                btnVerify.Visibility = Visibility.Collapsed;
                return;
            }
            txtSafety.FontSize = 20;
            txtSafety.Text = CryptoService.SafetyNumber(_crypto.PublicKey, p.PublicKey);
            btnVerify.Visibility = Visibility.Visible;
            btnVerify.Content = Localization.T(p.IsVerified ? "L_Unverify" : "L_MarkVerified");
            btnVerify.Style = (Style)FindResource(p.IsVerified ? "BtnLight" : "BtnSuccess");
        }

        private void btnVerify_Click(object sender, RoutedEventArgs e)
        {
            if (_active is not { } p) return;
            p.IsVerified = !p.IsVerified;
            p.IsNew = false;
            _trust.SetVerified(p.Fingerprint, p.IsVerified);
            RefreshHeader();
            RefreshSafety();
        }

        // =====================================================================
        //  GỬI TIN / FILE
        // =====================================================================

        private void btnSend_Click(object sender, RoutedEventArgs e) => _ = SendCurrentAsync();

        private void txtInput_PreviewKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Shift) == 0)
            {
                e.Handled = true;
                _ = SendCurrentAsync();
            }
            else if (e.Key == Key.V && (Keyboard.Modifiers & ModifierKeys.Control) != 0)
            {
                // Copy file trong Explorer → Ctrl+V vào ô chat = gửi file
                try
                {
                    if (Clipboard.ContainsFileDropList())
                    {
                        e.Handled = true;
                        SendFiles(Clipboard.GetFileDropList().Cast<string>().ToList());
                    }
                }
                catch { /* clipboard bận */ }
            }
        }

        private async Task SendCurrentAsync()
        {
            string text = txtInput.Text.Trim();
            if (string.IsNullOrEmpty(text)) return;
            if (_active is not { } peer) { SetStatus(Localization.T("L_SelectFirst")); return; }

            txtInput.Clear();
            var item = new ChatItem { Kind = ChatKind.Mine, Text = text, Status = "⏳" };
            AddChat(peer.Fingerprint, item);
            if (!peer.IsConnected) SetStatus(Fmt.F("L_Connecting", peer.Name));
            try
            {
                await Task.Run(() => _messaging.SendTextAsync(peer.Fingerprint, text));
                item.Status = "✓";
            }
            catch (Exception ex)
            {
                item.Status = "✗";
                AddChat(peer.Fingerprint, new ChatItem { Kind = ChatKind.System, Text = Fmt.F("L_SendFail", ex.Message) });
            }
        }

        private void btnFile_Click(object sender, RoutedEventArgs e)
        {
            if (_active is null) { SetStatus(Localization.T("L_SelectFirst")); return; }
            var dialog = new Microsoft.Win32.OpenFileDialog { Title = Localization.T("L_ChooseFile"), Multiselect = true };
            if (dialog.ShowDialog(this) != true) return;
            SendFiles(dialog.FileNames);
        }

        private void SendFiles(IEnumerable<string> paths)
        {
            if (_active is not { } peer) { SetStatus(Localization.T("L_SelectFirst")); return; }
            foreach (string path in paths)
            {
                if (Directory.Exists(path))
                {
                    AddChat(peer.Fingerprint, new ChatItem { Kind = ChatKind.System, Text = Fmt.F("L_SkipFolder", Path.GetFileName(path)) });
                    continue;
                }
                try { _files.StartSend(peer.Fingerprint, path); }
                catch (Exception ex)
                {
                    AddChat(peer.Fingerprint, new ChatItem { Kind = ChatKind.System, Text = Fmt.F("L_SendFail", ex.Message) });
                }
            }
        }

        // ---------- Kéo-thả ----------

        private bool CanDrop(DragEventArgs e) => _active is not null && e.Data.GetDataPresent(DataFormats.FileDrop);

        private void Window_DragEnter(object sender, DragEventArgs e)
        {
            e.Effects = CanDrop(e) ? DragDropEffects.Copy : DragDropEffects.None;
            if (CanDrop(e)) pnlDrop.Visibility = Visibility.Visible;
            e.Handled = true;
        }

        private void Window_DragOver(object sender, DragEventArgs e)
        {
            e.Effects = CanDrop(e) ? DragDropEffects.Copy : DragDropEffects.None;
            e.Handled = true;
        }

        private void Window_DragLeave(object sender, DragEventArgs e) => pnlDrop.Visibility = Visibility.Collapsed;

        private void Window_Drop(object sender, DragEventArgs e)
        {
            pnlDrop.Visibility = Visibility.Collapsed;
            if (!CanDrop(e)) return;
            if (e.Data.GetData(DataFormats.FileDrop) is string[] files) SendFiles(files);
        }

        // ---------- Nút trên thẻ transfer ----------

        private static TransferViewModel? TransferOf(object sender)
            => (sender as FrameworkElement)?.DataContext as TransferViewModel;

        private void TransferAccept_Click(object sender, RoutedEventArgs e)
        {
            if (TransferOf(sender) is { } t) _ = _files.AcceptAsync(t.Id);
        }

        private void TransferDecline_Click(object sender, RoutedEventArgs e)
        {
            if (TransferOf(sender) is { } t) _ = _files.RejectAsync(t.Id);
        }

        private void TransferCancel_Click(object sender, RoutedEventArgs e)
        {
            if (TransferOf(sender) is { } t) _files.Cancel(t.Id);
        }

        private void TransferOpen_Click(object sender, RoutedEventArgs e)
        {
            if (TransferOf(sender) is { LocalPath: { } path } && File.Exists(path))
                StartProcess("explorer.exe", $"/select,\"{path}\"");
        }

        // =====================================================================
        //  SIDEBAR
        // =====================================================================

        private async void btnScan_Click(object sender, RoutedEventArgs e)
        {
            btnScan.IsEnabled = false;
            SetStatus(Localization.T("L_Scanning"));
            try
            {
                await _discovery.ScanAsync();
                await Task.Delay(400); // chờ Reply về
                int online = _peers.Count(p => p.IsOnline);
                SetStatus(online > 0 ? Fmt.F("L_ScanDone", online) : Localization.T("L_ScanNone"));
            }
            catch (Exception ex) { SetStatus(Fmt.F("L_ScanError", ex.Message)); }
            finally { btnScan.IsEnabled = true; }
        }

        private void txtManual_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) btnConnect_Click(sender, e);
        }

        private async void btnConnect_Click(object sender, RoutedEventArgs e)
        {
            string input = txtManual.Text.Trim();
            if (string.IsNullOrEmpty(input)) return;

            // Chấp nhận "192.168.1.5", "192.168.1.5:8890", "[fe80::1]:8889", "pc-name", hoặc chỉ "8890" (→ 127.0.0.1)
            string host; int port = MessagingService.DefaultPort;
            if (int.TryParse(input, out int onlyPort) && onlyPort is > 0 and < 65536)
            {
                host = "127.0.0.1"; port = onlyPort;
            }
            else if (IPEndPoint.TryParse(input, out var ep) && (input.Contains("]:") || input.Count(c => c == ':') == 1))
            {
                host = ep.Address.ToString(); port = ep.Port == 0 ? MessagingService.DefaultPort : ep.Port;
            }
            else
            {
                int idx = input.LastIndexOf(':');
                if (idx > 0 && input.IndexOf(':') == idx && int.TryParse(input[(idx + 1)..], out int p2))
                { host = input[..idx]; port = p2; }
                else host = input.Trim('[', ']');
            }

            btnConnect.IsEnabled = false;
            SetStatus(Fmt.F("L_Connecting", $"{host}:{port}"));
            try
            {
                var info = await Task.Run(() => _messaging.ConnectAsync(host, port));
                txtManual.Clear();
                OnSessionEstablished(info); // có thể đến trước event — idempotent
                SelectPeer(GetPeer(info.Fingerprint, info.Name));
            }
            catch (PeerUnavailableException ex) when (ex.Reason == CloseReason.SelfConnection)
            {
                SetStatus(Fmt.F("L_ConnectFail", Localization.T("L_SelfConnect")));
            }
            catch (Exception ex) { SetStatus(Fmt.F("L_ConnectFail", ex.Message)); }
            finally { btnConnect.IsEnabled = true; }
        }

        private void btnCopyId_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Clipboard.SetText(_crypto.Fingerprint);
                SetStatus(Localization.T("L_Copied"));
            }
            catch { /* clipboard đang bị app khác giữ */ }
        }

        private void btnOpenDownloads_Click(object sender, RoutedEventArgs e)
            => StartProcess("explorer.exe", $"\"{_profile.DownloadDir}\"");

        private void btnLang_Click(object sender, RoutedEventArgs e)
        {
            Localization.Toggle();
            foreach (var p in _peers) p.RefreshTexts();
            foreach (var t in _transfers.Values) t.RefreshTexts();
            UpdatePeerCount();
            UpdateIdentityCard();
            RefreshHeader();
            if (pnlSafety.Visibility == Visibility.Visible) RefreshSafety();
        }

        // =====================================================================
        //  HIỂN THỊ TRẠNG THÁI
        // =====================================================================

        private void UpdateIdentityCard()
        {
            txtMyName.Text = _profile.DisplayName;
            var ifaces = _discovery.Interfaces;
            txtIP.Text = _discovery.Primary?.Address.ToString() ?? "127.0.0.1";
            txtIP.ToolTip = Localization.T("L_InterfacesTip") + "\n" +
                            (ifaces.Count == 0 ? "—" : string.Join("\n", ifaces.Select(i => "• " + i)));
            txtFingerprint.Text = _crypto.Fingerprint;
            txtPorts.Text = $"TCP :{_messaging.ListenPort}   UDP :{DiscoveryService.Port}" +
                            (_discovery.ListeningOnSharedPort ? "" : " (✗)") +
                            $"   ·   {ifaces.Count} NIC";
        }

        private void UpdatePeerCount()
        {
            int online = _peers.Count(p => p.IsOnline);
            txtOnlineCount.Text = online > 0 ? Fmt.F("L_OnlineCount", online) : "";
        }

        private void UpdateNetStats()
        {
            long sent = _messaging.BytesSent, recv = _messaging.BytesReceived;
            double dt = Math.Max(0.001, (DateTime.UtcNow - _lastStatsAt).TotalSeconds);
            double up = (sent - _lastSent) / dt, down = (recv - _lastRecv) / dt;
            _lastSent = sent; _lastRecv = recv; _lastStatsAt = DateTime.UtcNow;

            txtNetStats.Text = $"{_messaging.SessionCount} session(s)   " +
                               $"↑ {Fmt.Bytes(up)}/s  ↓ {Fmt.Bytes(down)}/s   " +
                               $"Σ ↑ {Fmt.Bytes(sent)}  ↓ {Fmt.Bytes(recv)}";
        }

        private void SetStatus(string text) => txtStatus.Text = text;

        /// <summary>Nháy nút trên taskbar khi có tin/file mới mà cửa sổ không được focus (không cướp focus).</summary>
        private void FlashIfInactive()
        {
            if (IsActive) return;
            try
            {
                var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                var info = new NativeMethods.FLASHWINFO
                {
                    cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.FLASHWINFO>(),
                    hwnd = hwnd,
                    dwFlags = NativeMethods.FLASHW_TRAY | NativeMethods.FLASHW_TIMERNOFG,
                };
                NativeMethods.FlashWindowEx(ref info);
            }
            catch { }
        }

        private static class NativeMethods
        {
            public const uint FLASHW_TRAY = 0x2, FLASHW_TIMERNOFG = 0xC;

            [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
            public struct FLASHWINFO
            {
                public uint cbSize;
                public IntPtr hwnd;
                public uint dwFlags;
                public uint uCount;
                public uint dwTimeout;
            }

            [System.Runtime.InteropServices.DllImport("user32.dll")]
            [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public static extern bool FlashWindowEx(ref FLASHWINFO pwfi);
        }

        private static void StartProcess(string file, string args)
        {
            try { Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = true }); }
            catch { }
        }

        protected override void OnClosed(EventArgs e)
        {
            _statsTimer.Stop();
            _files.Dispose();
            _discovery.Dispose();   // Bye UDP → mọi người thấy mình offline ngay
            _messaging.Dispose();   // Bye TCP trên từng phiên
            _crypto.Dispose();
            _profile.Dispose();
            base.OnClosed(e);
        }
    }
}
