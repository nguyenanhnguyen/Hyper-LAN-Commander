using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using networkApp.Security;

namespace networkApp
{
    /// <summary>Các dịch vụ mà Security Center cần — MainWindow tạo và truyền vào.</summary>
    public sealed class SecurityContext
    {
        public required MessagingService Messaging { get; init; }
        public required DiscoveryService Discovery { get; init; }
        public required SecurityLog Log { get; init; }
        public required ThreatMonitor Monitor { get; init; }
        public required LinkTestService LinkTest { get; init; }
        public required string MachineName { get; init; }
        public required string Fingerprint { get; init; }
        public required string ReportFolder { get; init; }
        public required Func<IEnumerable<PeerOption>> ConnectedPeers { get; init; }
    }

    public partial class SecurityCenterView : UserControl
    {
        public static readonly DependencyProperty EavesdropperModeProperty =
            DependencyProperty.Register(nameof(EavesdropperMode), typeof(bool), typeof(SecurityCenterView));

        public bool EavesdropperMode
        {
            get => (bool)GetValue(EavesdropperModeProperty);
            set => SetValue(EavesdropperModeProperty, value);
        }

        private SecurityContext? _ctx;
        private readonly ObservableCollection<SecurityEvent> _events = new();
        private readonly ObservableCollection<HostRowVm> _hosts = new();
        private readonly Dictionary<string, HostRowVm> _hostByIp = new();
        private readonly ObservableCollection<TraceRowVm> _trace = new();
        private readonly ConcurrentQueue<FrameTrace> _traceQueue = new();
        private readonly ObservableCollection<LabRowVm> _lab = new();
        private readonly List<HostResult> _lastLan = new();
        private HostAuditReport? _lastAudit;
        private CancellationTokenSource? _scanCts, _toolCts;
        private DispatcherTimer? _traceTimer;
        private long _traceFrames, _traceBytes;
        private readonly List<byte> _entropySample = new();

        /// <summary>Số sự kiện mức Cao/Nghiêm trọng chưa xem — MainWindow hiện badge.</summary>
        public event Action<int>? UnseenAlertsChanged;
        private int _unseen;
        public bool IsShown { get; set; }

        public SecurityCenterView()
        {
            InitializeComponent();
            lstEvents.ItemsSource = _events;
            lstHosts.ItemsSource = _hosts;
            lstTrace.ItemsSource = _trace;
            lstLab.ItemsSource = _lab;
        }

        public void Initialize(SecurityContext ctx)
        {
            _ctx = ctx;
            foreach (var e in ctx.Log.Snapshot()) _events.Insert(0, e);
            ctx.Log.Added += ev => Dispatcher.BeginInvoke(() => OnEvent(ev));
            ctx.Monitor.Updated += () => Dispatcher.BeginInvoke(RefreshOverview);
            ctx.Discovery.NetworkChanged += () => Dispatcher.BeginInvoke(FillInterfaces);

            // Protocol Inspector: sự kiện tới từ thread mạng → gom vào hàng đợi, UI rút 5 lần/giây
            ctx.Messaging.FrameTraced += t => _traceQueue.Enqueue(t);
            ctx.Messaging.TraceEnabled = true;
            _traceTimer = new DispatcherTimer(TimeSpan.FromMilliseconds(200), DispatcherPriority.Background,
                (_, _) => FlushTrace(), Dispatcher);
            _traceTimer.Start();

            FillInterfaces();
            UpdateEventsEmpty();
            RefreshOverview();
            _ = RunAuditAsync();
        }

        public void MarkSeen()
        {
            _unseen = 0;
            UnseenAlertsChanged?.Invoke(0);
        }

        public void RefreshTexts()
        {
            RefreshOverview();
            if (_lastAudit is not null) ShowAudit(_lastAudit);
        }

        private void OnEvent(SecurityEvent ev)
        {
            _events.Insert(0, ev);
            if (_events.Count > 1000) _events.RemoveAt(_events.Count - 1);
            UpdateEventsEmpty();
            if (ev.Severity >= Severity.High && !IsShown)
            {
                _unseen++;
                UnseenAlertsChanged?.Invoke(_unseen);
            }
            RefreshOverview();
        }

        private void UpdateEventsEmpty() => txtNoEvents.Visibility = _events.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        // =====================================================================
        //  TỔNG QUAN
        // =====================================================================

        private void RefreshOverview()
        {
            if (_ctx is null) return;
            if (_lastAudit is { } a)
            {
                ovScore.Text = $"{a.Score}";
                ovScore.Foreground = ScoreBrush(a.Score);
                ovScoreSub.Text = Localization.Pick($"{a.Findings.Count(f => f.Severity >= Severity.Medium)} vấn đề cần xử lý",
                                                    $"{a.Findings.Count(f => f.Severity >= Severity.Medium)} issue(s) to fix");
            }
            if (_lastLan.Count > 0)
            {
                int risky = _lastLan.Count(h => h.MaxRisk >= Severity.High);
                ovLan.Text = $"{_lastLan.Count}";
                ovLanSub.Text = Localization.Pick($"{risky} máy có dịch vụ rủi ro cao", $"{risky} host(s) with high-risk services");
            }
            else
            {
                ovLan.Text = "—";
                ovLanSub.Text = Localization.T("S_NotRun");
            }

            var m = _ctx.Monitor;
            int arpAlerts = _events.Count(e => e.Category == SecurityCategory.Arp && e.Severity >= Severity.High);
            ovMon.Text = arpAlerts == 0 ? "OK" : $"⚠ {arpAlerts}";
            ovMon.Foreground = arpAlerts == 0 ? (System.Windows.Media.Brush)FindResource("SuccessText") : (System.Windows.Media.Brush)FindResource("DangerText");
            ovMonSub.Text = Localization.Pick($"{m.DeviceCount} thiết bị · {m.ScanCount} lần quét · GW {m.GatewayInfo}",
                                              $"{m.DeviceCount} devices · {m.ScanCount} sweeps · GW {m.GatewayInfo}");

            if (_lab.Count > 0)
            {
                int blocked = _lab.Count(r => r.Blocked);
                ovLab.Text = $"{blocked}/{_lab.Count}";
                ovLab.Foreground = blocked == _lab.Count ? (System.Windows.Media.Brush)FindResource("SuccessText") : (System.Windows.Media.Brush)FindResource("DangerText");
                ovLabSub.Text = Localization.Pick("đòn tấn công bị chặn", "attacks blocked");
            }
            else
            {
                ovLab.Text = "—";
                ovLabSub.Text = Localization.T("S_NotRun");
            }

            ovProto.Text = $"{_ctx.Messaging.SessionCount}";
            ovProtoSub.Text = Localization.Pick(
                $"phiên E2E · {_ctx.Messaging.RejectedConnections} kết nối bị loại vì lý do an ninh · {_ctx.Messaging.RefusedConnections} bị chặn flood",
                $"E2E session(s) · {_ctx.Messaging.RejectedConnections} rejected for security · {_ctx.Messaging.RefusedConnections} flood-refused");
        }

        private System.Windows.Media.Brush ScoreBrush(int score)
            => (System.Windows.Media.Brush)FindResource(score >= 80 ? "SuccessText" : score >= 50 ? "WarnText" : "DangerText");

        // =====================================================================
        //  KIỂM ĐỊNH LAN
        // =====================================================================

        private void FillInterfaces()
        {
            if (_ctx is null) return;
            var sel = (cmbIface.SelectedItem as LocalInterface)?.Address;
            var list = _ctx.Discovery.Interfaces.Where(i => Knowledge.IsAuditable(i.Address)).ToList();
            cmbIface.ItemsSource = list;
            cmbIface.SelectedItem = list.FirstOrDefault(i => i.Address.Equals(sel)) ?? list.FirstOrDefault();
        }

        private async void btnScanLan_Click(object sender, RoutedEventArgs e)
        {
            if (_ctx is null || cmbIface.SelectedItem is not LocalInterface iface) return;
            if (chkConsent.IsChecked != true)
            {
                txtLanStatus.Text = Localization.T("S_NeedConsent");
                txtLanStatus.Foreground = (System.Windows.Media.Brush)FindResource("DangerText");
                return;
            }
            txtLanStatus.Foreground = (System.Windows.Media.Brush)FindResource("Muted");

            _scanCts = new CancellationTokenSource();
            btnScanLan.IsEnabled = false;
            btnStopLan.IsEnabled = true;
            _hosts.Clear();
            _hostByIp.Clear();
            bool whole = chkWhole.IsChecked == true; // đọc control TRƯỚC khi sang thread nền
            var token = _scanCts.Token;
            var (first, last) = LanScanner.RangeFor(iface, whole);
            string range = $"{Knowledge.FromUInt(first)} – {Knowledge.FromUInt(last)}";
            var sw = Stopwatch.StartNew();

            var progress = new Progress<ScanProgress>(p =>
            {
                barLan.Value = p.Phase == "sweep" ? p.Done * 50.0 / Math.Max(1, p.Total) : 50 + p.Done * 50.0 / Math.Max(1, p.Total);
                txtLanStatus.Text = p.Phase == "sweep"
                    ? Localization.Pick($"Pha 1/3 · ping sweep {range} · {p.Done}/{p.Total}", $"Phase 1/3 · ping sweep {range} · {p.Done}/{p.Total}")
                    : Localization.Pick($"Pha 3/3 · quét cổng & thăm dò dịch vụ · {p.Done}/{p.Total} máy", $"Phase 3/3 · port scan & service probing · {p.Done}/{p.Total} hosts");
            });

            try
            {
                var result = await Task.Run(() => new LanScanner().ScanAsync(iface, whole, progress,
                    h => Dispatcher.BeginInvoke(() => UpsertHost(h)), token));
                _lastLan.Clear();
                _lastLan.AddRange(result);
                foreach (var h in result) UpsertHost(h); // đã ở UI thread — cập nhật bản cuối cùng

                int risky = result.Count(h => h.MaxRisk >= Severity.High);
                txtLanStatus.Text = Localization.Pick(
                    $"Xong trong {sw.Elapsed.TotalSeconds:0.0}s · {result.Count} máy · {result.Sum(h => h.Services.Count)} dịch vụ mở · {risky} máy rủi ro cao",
                    $"Done in {sw.Elapsed.TotalSeconds:0.0}s · {result.Count} hosts · {result.Sum(h => h.Services.Count)} open services · {risky} high-risk hosts");
                barLan.Value = 100;

                foreach (var h in result)
                    foreach (var s in h.Services.Where(s => s.Risk >= Severity.High && !h.IsSelf))
                        _ctx.Log.Add(s.Risk, SecurityCategory.Lan,
                            Localization.Pick($"{h.Ip} mở {s.Service} (TCP {s.Port})", $"{h.Ip} exposes {s.Service} (TCP {s.Port})"),
                            s.Issues.Count > 0 ? string.Join("; ", s.Issues) : Localization.Pick(Knowledge.Describe(s.Port).WhyVi, Knowledge.Describe(s.Port).WhyEn),
                            dedupeKey: $"lan:{h.Ip}:{s.Port}");
                RefreshOverview();
            }
            catch (OperationCanceledException) { txtLanStatus.Text = Localization.Pick("Đã dừng.", "Stopped."); }
            catch (Exception ex) { txtLanStatus.Text = ex.Message; }
            finally
            {
                btnScanLan.IsEnabled = true;
                btnStopLan.IsEnabled = false;
            }
        }

        private void UpsertHost(HostResult h)
        {
            string ip = h.Ip.ToString();
            if (_hostByIp.TryGetValue(ip, out var vm)) { vm.Update(h); return; }
            vm = new HostRowVm(h);
            _hostByIp[ip] = vm;
            int idx = 0;
            while (idx < _hosts.Count && _hosts[idx].SortKey < vm.SortKey) idx++;
            _hosts.Insert(idx, vm);
        }

        private void btnStopLan_Click(object sender, RoutedEventArgs e) => _scanCts?.Cancel();

        // =====================================================================
        //  MÁY NÀY
        // =====================================================================

        private void btnAudit_Click(object sender, RoutedEventArgs e) => _ = RunAuditAsync();

        private async Task RunAuditAsync()
        {
            btnAudit.IsEnabled = false;
            try
            {
                var report = await Task.Run(HostAudit.Run);
                _lastAudit = report;
                ShowAudit(report);
                foreach (var f in report.Findings.Where(f => f.Severity >= Severity.High))
                    _ctx?.Log.Add(f.Severity, SecurityCategory.Device, f.Title, f.Detail, dedupeKey: "dev:" + f.Title);
                RefreshOverview();
            }
            catch (Exception ex) { devFacts.Text = ex.Message; }
            finally { btnAudit.IsEnabled = true; }
        }

        private void ShowAudit(HostAuditReport r)
        {
            devScore.Text = $"{r.Score}";
            devScore.Foreground = ScoreBrush(r.Score);
            string fw = string.Join("  ", r.Firewall.Select(kv => $"{kv.Key}: {(kv.Value is null ? "?" : kv.Value.Value ? "ON" : "OFF")}"));
            string nets = string.Join(", ", r.Networks.Select(n => $"{n.Name} ({n.Category})"));
            string wifi = r.Wifi is null ? "" : $"\nWi-Fi: {r.Wifi.Ssid} · {r.Wifi.Authentication} · {r.Wifi.Cipher} · {r.Wifi.Signal} {r.Wifi.Band}";
            int exposed = r.Listeners.Count(l => l.Protocol.StartsWith("TCP") && l.IsExposed);
            devFacts.Text = $"Firewall — {fw}\n{nets}{wifi}\n" +
                            Localization.Pick($"{r.Listeners.Count} socket lắng nghe · {exposed} TCP lộ ra mạng",
                                              $"{r.Listeners.Count} listening sockets · {exposed} TCP exposed");
            lstFindings.ItemsSource = r.Findings.Select(f => new FindingRowVm { Severity = f.Severity, Title = f.Title, Detail = f.Detail }).ToList();
            ShowListeners();
        }

        private void chkExposed_Changed(object sender, RoutedEventArgs e) => ShowListeners();

        private void ShowListeners()
        {
            if (_lastAudit is null) return;
            bool onlyExposed = chkExposed.IsChecked == true;
            gridListeners.ItemsSource = _lastAudit.Listeners
                .Where(l => !onlyExposed || (l.IsExposed && !l.Address.Equals(System.Net.IPAddress.IPv6Loopback)))
                .OrderBy(l => l.Protocol).ThenBy(l => l.Port)
                .Select(l => new
                {
                    l.Protocol, Address = l.Address.ToString(), l.Port,
                    Service = Knowledge.Describe(l.Port).Service is "?" ? "" : Knowledge.Describe(l.Port).Service,
                    Process = l.ProcessName, l.Pid,
                }).ToList();
        }

        // =====================================================================
        //  SOI GIAO THỨC
        // =====================================================================

        private void FlushTrace()
        {
            if (_traceQueue.IsEmpty) return;
            int added = 0;
            while (_traceQueue.TryDequeue(out var t) && added < 300)
            {
                if (chkCapture.IsChecked != true) continue;
                _trace.Add(new TraceRowVm(t));
                _traceFrames += t.Aggregated;
                _traceBytes += t.WireBytes;
                if (t.Kind == "Sealed" && _entropySample.Count < 65536)
                    for (int i = 0; i + 1 < t.CipherHex.Length; i += 2)
                        _entropySample.Add(Convert.ToByte(t.CipherHex.Substring(i, 2), 16));
                added++;
            }
            while (_trace.Count > 600) _trace.RemoveAt(0);
            if (added == 0) return;
            txtTraceHint.Visibility = Visibility.Collapsed;
            double ent = SecurityLab.ShannonEntropy(_entropySample.ToArray());
            txtInspStats.Text = $"{_traceFrames:N0} records · {_traceBytes / 1024.0:N0} KB · ciphertext entropy {ent:0.00} bit/B (sample {_entropySample.Count:N0} B)";
            if (lstTrace.Items.Count > 0) lstTrace.ScrollIntoView(lstTrace.Items[^1]);
        }

        private void chkCapture_Changed(object sender, RoutedEventArgs e)
        {
            if (_ctx is not null) _ctx.Messaging.TraceEnabled = chkCapture.IsChecked == true;
        }

        private void chkEaves_Changed(object sender, RoutedEventArgs e) => EavesdropperMode = chkEaves.IsChecked == true;

        private void btnClearTrace_Click(object sender, RoutedEventArgs e)
        {
            _trace.Clear();
            _traceFrames = _traceBytes = 0;
            _entropySample.Clear();
            txtInspStats.Text = "";
            txtTraceHint.Visibility = Visibility.Visible;
        }

        // =====================================================================
        //  ATTACK LAB
        // =====================================================================

        private async void btnLab_Click(object sender, RoutedEventArgs e)
        {
            btnLab.IsEnabled = false;
            _lab.Clear();
            barLab.Value = 0;
            var sw = Stopwatch.StartNew();
            txtLabStatus.Text = Localization.Pick("Đang tấn công…", "Attacking…");
            try
            {
                await Task.Run(() => new SecurityLab().RunAllAsync(r => Dispatcher.BeginInvoke(() =>
                {
                    _lab.Add(new LabRowVm(r));
                    barLab.Value = _lab.Count;
                    txtLabStatus.Text = $"{_lab.Count}/{SecurityLab.ScenarioCount} · {r.Attack}";
                    lstLab.ScrollIntoView(_lab[^1]);
                }), CancellationToken.None));
                await Dispatcher.InvokeAsync(() => { }, DispatcherPriority.Background); // chờ các kết quả cuối được thêm
                int blocked = _lab.Count(x => x.Blocked);
                txtLabStatus.Text = Localization.Pick($"{blocked}/{_lab.Count} đòn bị chặn · {sw.Elapsed.TotalSeconds:0.0}s",
                                                      $"{blocked}/{_lab.Count} attacks blocked · {sw.Elapsed.TotalSeconds:0.0}s");
                _ctx?.Log.Add(blocked == _lab.Count ? Severity.Info : Severity.Critical, SecurityCategory.Protocol,
                    Localization.Pick($"Attack Lab: {blocked}/{_lab.Count} đòn bị chặn", $"Attack Lab: {blocked}/{_lab.Count} attacks blocked"),
                    string.Join(" · ", _lab.Select(x => (x.Blocked ? "✓ " : "✗ ") + x.Attack)));
                RefreshOverview();
            }
            catch (Exception ex) { txtLabStatus.Text = ex.Message; }
            finally { btnLab.IsEnabled = true; }
        }

        // =====================================================================
        //  CÔNG CỤ
        // =====================================================================

        private void Console(string line) => Dispatcher.BeginInvoke(() =>
        {
            txtConsole.AppendText(line + Environment.NewLine);
            txtConsole.ScrollToEnd();
        });

        private async Task RunToolAsync(Func<CancellationToken, Task> tool)
        {
            _toolCts?.Cancel();
            _toolCts = new CancellationTokenSource();
            var ct = _toolCts.Token;
            try { await Task.Run(() => tool(ct), ct); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Console("error: " + ex.Message); }
            Console("");
        }

        private string Target()
        {
            string t = txtTarget.Text.Trim();
            return t.Length > 0 ? t : (_ctx?.Monitor.GatewayInfo.Split(' ').FirstOrDefault() is { Length: > 0 } gw ? gw : "1.1.1.1");
        }

        private void btnPing_Click(object sender, RoutedEventArgs e)
        {
            string t = Target();
            _ = RunToolAsync(ct => NetTools.PingAsync(t, 6, Console, ct));
        }

        private void btnTrace_Click(object sender, RoutedEventArgs e)
        {
            string t = Target();
            _ = RunToolAsync(ct => NetTools.TracerouteAsync(t, Console, ct));
        }

        private void btnDns_Click(object sender, RoutedEventArgs e)
        {
            string t = txtTarget.Text.Trim();
            if (t.Length == 0) t = "example.com";
            _ = RunToolAsync(_ => NetTools.DnsLookupAsync(t, Console));
        }

        private void cmbPeers_DropDownOpened(object? sender, EventArgs e)
        {
            if (_ctx is null) return;
            var peers = _ctx.ConnectedPeers().ToList();
            cmbPeers.ItemsSource = peers.Count > 0 ? peers : new List<object> { Localization.T("S_NoPeers") };
        }

        private void btnLinkTest_Click(object sender, RoutedEventArgs e)
        {
            if (_ctx is null) return;
            if (cmbPeers.SelectedItem is not PeerOption peer)
            {
                cmbPeers_DropDownOpened(null, EventArgs.Empty);
                cmbPeers.IsDropDownOpen = true;
                return;
            }
            var link = _ctx.LinkTest;
            _ = RunToolAsync(async ct =>
            {
                Console($"LINK TEST → {peer.Name} [{peer.Fingerprint}] over AES-256-GCM session");
                var r = await link.RunAsync(peer.Fingerprint, new Progress<string>(_ => { }), ct);
                Console($"  RTT   min/avg/max = {r.RttMinMs:0.00} / {r.RttAvgMs:0.00} / {r.RttMaxMs:0.00} ms");
                Console($"  jitter            = {r.JitterMs:0.00} ms   (RFC 3550 mean |ΔRTT|)");
                Console($"  echo loss         = {r.EchoLost}/20");
                Console($"  throughput        = {r.ThroughputMBps:0.0} MB/s  ({r.ThroughputMBps * 8:0} Mbit/s, {r.Bytes >> 20} MB encrypted in {r.Seconds:0.00}s)");
            });
        }

        // =====================================================================
        //  BÁO CÁO
        // =====================================================================

        private void btnExport_Click(object sender, RoutedEventArgs e)
        {
            if (_ctx is null) return;
            try
            {
                string path = ReportExporter.Export(_ctx.ReportFolder, _ctx.MachineName, _ctx.Fingerprint, _lastAudit,
                    _lastLan, _lab.Select(l => l.Result).ToList(), _ctx.Log.Snapshot());
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show(Window.GetWindow(this)!, ex.Message, "Export", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        public void Shutdown()
        {
            _scanCts?.Cancel();
            _toolCts?.Cancel();
            _traceTimer?.Stop();
        }
    }
}
