using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp.Security
{
    /// <summary>
    /// IDS thu nhỏ cho LAN (cùng ý tưởng với arpwatch / XArp), chạy nền mỗi 4 giây, không cần admin:
    ///
    ///  • GATEWAY MAC ĐỔI — dấu hiệu kinh điển của ARP spoofing: kẻ tấn công gửi ARP reply giả
    ///    "IP router là MAC của tao" để mọi traffic ra Internet đi qua máy hắn (MITM).
    ///  • MỘT MAC GIỮ NHIỀU IP, trong đó có IP gateway — chữ ký của công cụ như arpspoof/Bettercap/Ettercap.
    ///  • IP ĐỔI MAC — xung đột IP hoặc thiết bị bị thay.
    ///  • THIẾT BỊ MỚI vào mạng (MAC chưa từng thấy) — phát hiện máy lạ cắm vào LAN.
    ///  • GATEWAY / DNS SERVER của máy mình đổi — dấu hiệu DHCP giả (rogue DHCP) hoặc malware đổi DNS.
    /// </summary>
    public sealed class ThreatMonitor : IDisposable
    {
        private readonly SecurityLog _log;
        private readonly CancellationTokenSource _cts = new();
        private readonly Dictionary<string, string> _ipToMac = new();     // ip → mac (baseline)
        private readonly HashSet<string> _knownMacs = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> _gatewayMac = new();  // gatewayIp → mac
        private string _netSignature = "";
        private bool _baselined;

        public int ScanCount { get; private set; }
        public int DeviceCount { get; private set; }
        public string GatewayInfo { get; private set; } = "";
        public event Action? Updated;

        public ThreatMonitor(SecurityLog log) => _log = log;

        public void Start() => _ = Task.Run(LoopAsync);

        private async Task LoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                try { Tick(); }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[ThreatMonitor] {ex.Message}"); }
                try { await Task.Delay(4000, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        /// <summary>Một vòng kiểm tra (public để Security Center bấm "kiểm tra ngay").</summary>
        public void Tick()
        {
            lock (_tickLock) TickLocked();
        }

        private readonly object _tickLock = new();

        private void TickLocked()
        {
            var gateways = CurrentGateways();
            CheckNetworkConfig(gateways);

            var table = NetNative.GetArpTable()
                .Where(e => e.IsUsable && !Knowledge.IsMulticastOrBroadcastMac(e.Mac) && Knowledge.IsAuditable(e.Address))
                .GroupBy(e => e.Address.ToString()).Select(g => g.First()).ToList();

            // ----- 1. Gateway MAC -----
            var gwInfo = new List<string>();
            foreach (var gw in gateways)
            {
                string ip = gw.ToString();
                var entry = table.FirstOrDefault(e => e.Address.Equals(gw));
                if (entry is null) continue;
                gwInfo.Add($"{ip} → {entry.Mac}");
                if (_gatewayMac.TryGetValue(ip, out var oldMac) && !oldMac.Equals(entry.Mac, StringComparison.OrdinalIgnoreCase))
                {
                    _log.Add(Severity.Critical, SecurityCategory.Arp,
                        Localization.Pick("MAC của gateway THAY ĐỔI — nghi ARP spoofing", "Gateway MAC CHANGED — possible ARP spoofing"),
                        Localization.Pick(
                            $"Router {ip}: {oldMac} → {entry.Mac}. Nếu không vừa thay router, có thể ai đó đang chặn giữa bạn và Internet (MITM). Kiểm tra bằng `arp -a`, ngắt mạng nếu nghi ngờ.",
                            $"Router {ip}: {oldMac} → {entry.Mac}. Unless the router was replaced, someone may be intercepting your traffic (MITM). Verify with `arp -a`; disconnect if in doubt."),
                        dedupeKey: $"gwmac:{ip}:{entry.Mac}");
                }
                _gatewayMac[ip] = entry.Mac;
            }
            GatewayInfo = string.Join(", ", gwInfo);

            // ----- 2. Một MAC giữ nhiều IP (có gateway) -----
            foreach (var g in table.GroupBy(e => e.Mac, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1))
            {
                var ips = g.Select(e => e.Address).ToList();
                bool claimsGateway = ips.Any(ip => gateways.Any(gw => gw.Equals(ip)));
                if (!claimsGateway) continue; // nhiều IP/1 MAC không có gateway: thường là máy ảo/alias — bỏ qua
                _log.Add(Severity.High, SecurityCategory.Arp,
                    Localization.Pick("Một MAC nhận nhiều IP, gồm cả gateway", "One MAC claims several IPs including the gateway"),
                    Localization.Pick(
                        $"{g.Key} ↔ {string.Join(", ", ips)} — đúng chữ ký của arpspoof/Bettercap (đầu độc ARP 2 chiều).",
                        $"{g.Key} ↔ {string.Join(", ", ips)} — the signature of arpspoof/Bettercap (two-way ARP poisoning)."),
                    dedupeKey: $"multi:{g.Key}:{string.Join(",", ips)}");
            }

            // ----- 3. IP đổi MAC / 4. thiết bị mới -----
            foreach (var e in table)
            {
                string ip = e.Address.ToString();
                bool isGw = gateways.Any(gw => gw.Equals(e.Address));
                if (_ipToMac.TryGetValue(ip, out var prev) && !prev.Equals(e.Mac, StringComparison.OrdinalIgnoreCase) && !isGw)
                {
                    _log.Add(Severity.Medium, SecurityCategory.Arp,
                        Localization.Pick("Địa chỉ IP đổi chủ (MAC khác)", "IP address changed owner (different MAC)"),
                        $"{ip}: {prev} → {e.Mac}", dedupeKey: $"ipmac:{ip}:{e.Mac}");
                }
                _ipToMac[ip] = e.Mac;

                if (_knownMacs.Add(e.Mac) && _baselined)
                {
                    string vendor = Knowledge.Vendor(e.Mac);
                    _log.Add(Severity.Info, SecurityCategory.Lan,
                        Localization.Pick("Thiết bị mới xuất hiện trong mạng", "New device joined the network"),
                        $"{ip} · {e.Mac}{(vendor.Length > 0 ? " · " + vendor : "")}", dedupeKey: $"new:{e.Mac}");
                }
            }

            DeviceCount = table.Count;
            ScanCount++;
            _baselined = true;
            try { Updated?.Invoke(); } catch { }
        }

        private void CheckNetworkConfig(List<IPAddress> gateways)
        {
            var dns = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces()
                             .Where(n => n.OperationalStatus == OperationalStatus.Up &&
                                         n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                    dns.AddRange(ni.GetIPProperties().DnsAddresses
                        .Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()));
            }
            catch { }

            string sig = $"gw={string.Join(",", gateways.Select(g => g.ToString()).OrderBy(x => x))};dns={string.Join(",", dns.Distinct().OrderBy(x => x))}";
            if (_baselined && sig != _netSignature)
            {
                _log.Add(Severity.Medium, SecurityCategory.Network,
                    Localization.Pick("Gateway / DNS server của máy thay đổi", "This machine's gateway / DNS servers changed"),
                    Localization.Pick(
                        $"Trước: {_netSignature}\nNay: {sig}\nBình thường nếu bạn vừa đổi mạng. Nếu không: nghi DHCP giả (rogue DHCP) hoặc malware đổi DNS.",
                        $"Before: {_netSignature}\nNow: {sig}\nNormal if you just switched networks. Otherwise: possible rogue DHCP or DNS-hijacking malware."),
                    dedupeKey: "netcfg:" + sig);
                // Đổi mạng thật → làm lại baseline ARP để không báo động giả hàng loạt
                _gatewayMac.Clear();
                _ipToMac.Clear();
            }
            _netSignature = sig;
        }

        private static List<IPAddress> CurrentGateways()
        {
            try
            {
                return NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                    .Select(g => g.Address)
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))
                    .Distinct().ToList();
            }
            catch { return new List<IPAddress>(); }
        }

        public void Dispose() => _cts.Cancel();
    }
}
