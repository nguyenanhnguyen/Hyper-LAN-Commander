using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp.Security
{
    /// <summary>Một dịch vụ mở được tìm thấy + các vấn đề an ninh phát hiện được.</summary>
    public sealed record ServiceFinding(int Port, string Service, Severity Risk, string Banner, List<string> Issues);

    public sealed class HostResult
    {
        public required IPAddress Ip { get; init; }
        public string Mac { get; set; } = "";
        public string Vendor { get; set; } = "";
        public string? HostName { get; set; }
        public int PingMs { get; set; } = -1;
        public bool IsSelf { get; set; }
        public bool IsGateway { get; set; }
        public bool PortsScanned { get; set; }
        public List<ServiceFinding> Services { get; } = new();

        public Severity MaxRisk => Services.Count == 0 ? Severity.Info : Services.Max(s => s.Risk);
    }

    public sealed record ScanProgress(string Phase, int Done, int Total);

    /// <summary>
    /// Kiểm định LAN KHÔNG XÂM NHẬP (giống Fing / Advanced IP Scanner / nmap -sT -sV mức nhẹ):
    ///
    ///  1. Ping sweep (ICMP bất đồng bộ, 128 luồng). Kể cả máy CHẶN ping vẫn phải trả lời ARP
    ///     để nhận gói → OS đã ghi nó vào bảng ARP.
    ///  2. Đọc bảng ARP → danh sách máy sống thật ở tầng 2 (IP + MAC + hãng sản xuất).
    ///  3. TCP connect scan các cổng hay bị khai thác + thăm dò dịch vụ:
    ///       banner (SSH/FTP/SMTP...), HTTP Server header & Basic-auth trên kênh rõ,
    ///       chứng chỉ TLS (hết hạn, tự ký, giao thức cũ), Redis không mật khẩu (PING → +PONG),
    ///       nhận diện peer Hyper-LAN qua gói Hello.
    ///
    /// Giới hạn an toàn: chỉ dải private/link-local, mặc định /24 quanh IP của mình, tối đa /22.
    /// Không thử mật khẩu, không gửi payload khai thác.
    /// </summary>
    public sealed class LanScanner
    {
        public const int MaxHosts = 1024;

        public static (uint First, uint Last) RangeFor(LocalInterface iface, bool wholeSubnet)
        {
            uint ip = Knowledge.ToUInt(iface.Address);
            int prefix = Math.Clamp(iface.PrefixLength, 0, 32);
            int effective = prefix >= 24 ? prefix : (wholeSubnet ? Math.Max(prefix, 22) : 24);
            uint mask = effective == 0 ? 0 : uint.MaxValue << (32 - effective);
            uint net = ip & mask, bcast = net | ~mask;
            if (effective >= 31) return (net, bcast);
            return (net + 1, bcast - 1);
        }

        public async Task<List<HostResult>> ScanAsync(LocalInterface iface, bool wholeSubnet,
            IProgress<ScanProgress> progress, Action<HostResult> onHost, CancellationToken ct)
        {
            if (!Knowledge.IsAuditable(iface.Address))
                throw new InvalidOperationException("Only private / link-local networks can be audited.");

            var (first, last) = RangeFor(iface, wholeSubnet);
            int total = (int)Math.Min(last - first + 1, MaxHosts);
            var hosts = new ConcurrentDictionary<uint, HostResult>();
            IPAddress? gateway = GatewayOf(iface);

            // ---------- Pha 1: ping sweep ----------
            int done = 0;
            var sem = new SemaphoreSlim(128);
            var tasks = new List<Task>();
            for (uint i = 0; i < total; i++)
            {
                uint addr = first + i;
                await sem.WaitAsync(ct).ConfigureAwait(false);
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        using var ping = new Ping();
                        var reply = await ping.SendPingAsync(Knowledge.FromUInt(addr), 600).ConfigureAwait(false);
                        if (reply.Status == IPStatus.Success)
                        {
                            var h = hosts.GetOrAdd(addr, a => new HostResult { Ip = Knowledge.FromUInt(a) });
                            h.PingMs = (int)reply.RoundtripTime;
                        }
                    }
                    catch { }
                    finally
                    {
                        sem.Release();
                        int d = Interlocked.Increment(ref done);
                        if (d % 8 == 0 || d == total) progress.Report(new ScanProgress("sweep", d, total));
                    }
                }, ct));
            }
            await Task.WhenAll(tasks).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();

            // ---------- Pha 2: bảng ARP (lộ ra cả máy chặn ICMP) ----------
            await Task.Delay(300, ct).ConfigureAwait(false);
            foreach (var e in NetNative.GetArpTable())
            {
                if (!e.IsUsable || Knowledge.IsMulticastOrBroadcastMac(e.Mac)) continue;
                uint a = Knowledge.ToUInt(e.Address);
                if (a < first || a > first + (uint)total - 1) continue;
                var h = hosts.GetOrAdd(a, x => new HostResult { Ip = Knowledge.FromUInt(x) });
                h.Mac = e.Mac;
            }

            uint self = Knowledge.ToUInt(iface.Address);
            var me = hosts.GetOrAdd(self, x => new HostResult { Ip = iface.Address });
            me.IsSelf = true;
            me.Mac = SelfMac(iface) ?? me.Mac;

            foreach (var h in hosts.Values)
            {
                h.Vendor = Knowledge.Vendor(h.Mac);
                h.IsGateway = gateway is not null && h.Ip.Equals(gateway);
                onHost(h);
            }

            // ---------- Pha 3: reverse DNS + quét cổng + thăm dò dịch vụ ----------
            var live = hosts.Values.OrderBy(h => Knowledge.ToUInt(h.Ip)).ToList();
            int hostDone = 0;
            progress.Report(new ScanProgress("ports", 0, live.Count));
            var hostSem = new SemaphoreSlim(8);
            await Task.WhenAll(live.Select(async h =>
            {
                await hostSem.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    h.HostName = await ReverseDnsAsync(h.Ip, ct).ConfigureAwait(false);
                    onHost(h);
                    await ScanPortsAsync(h, ct).ConfigureAwait(false);
                    h.PortsScanned = true;
                    onHost(h);
                }
                catch (OperationCanceledException) { throw; }
                catch { }
                finally
                {
                    hostSem.Release();
                    progress.Report(new ScanProgress("ports", Interlocked.Increment(ref hostDone), live.Count));
                }
            })).ConfigureAwait(false);

            return live;
        }

        private static IPAddress? GatewayOf(LocalInterface iface)
        {
            try
            {
                var ni = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == iface.Name);
                return ni?.GetIPProperties().GatewayAddresses
                         .Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
            }
            catch { return null; }
        }

        private static string? SelfMac(LocalInterface iface)
        {
            try
            {
                var ni = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Name == iface.Name);
                byte[]? b = ni?.GetPhysicalAddress().GetAddressBytes();
                return b is { Length: 6 } ? BitConverter.ToString(b) : null;
            }
            catch { return null; }
        }

        private static async Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct)
        {
            try
            {
                var t = Dns.GetHostEntryAsync(ip);
                if (await Task.WhenAny(t, Task.Delay(1500, ct)).ConfigureAwait(false) != t) return null;
                string name = t.Result.HostName;
                return name == ip.ToString() ? null : name;
            }
            catch { return null; }
        }

        // ==================== QUÉT CỔNG ====================

        private static async Task ScanPortsAsync(HostResult h, CancellationToken ct)
        {
            var sem = new SemaphoreSlim(24);
            var found = new ConcurrentBag<ServiceFinding>();
            await Task.WhenAll(Knowledge.Ports.Select(async p =>
            {
                await sem.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var f = await ProbeAsync(h.Ip, p, ct).ConfigureAwait(false);
                    if (f is not null) found.Add(f);
                }
                finally { sem.Release(); }
            })).ConfigureAwait(false);
            lock (h.Services)
            {
                h.Services.Clear();
                h.Services.AddRange(found.OrderBy(f => f.Port));
            }
        }

        /// <summary>TCP connect (bắt tay 3 bước đầy đủ — không cần raw socket/admin) rồi thăm dò dịch vụ.</summary>
        internal static async Task<ServiceFinding?> ProbeAsync(IPAddress ip, PortInfo p, CancellationToken ct)
        {
            using var client = new TcpClient(AddressFamily.InterNetwork);
            using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                cts.CancelAfter(700);
                try { await client.ConnectAsync(ip, p.Port, cts.Token).ConfigureAwait(false); }
                catch { return null; } // đóng / bị lọc
            }

            var issues = new List<string>();
            string banner = "";
            Severity risk = p.Risk;
            try
            {
                var stream = client.GetStream();
                switch (p.Port)
                {
                    case 443 or 8443:
                        banner = await ProbeTlsAsync(stream, ip, issues).ConfigureAwait(false);
                        if (issues.Count > 0) risk = (Severity)Math.Max((int)risk, (int)Severity.Medium);
                        break;
                    case 80 or 8080 or 5000:
                        banner = await ProbeHttpAsync(stream, ip, issues).ConfigureAwait(false);
                        if (issues.Count > 0) risk = Severity.High;
                        break;
                    case 6379:
                        banner = await ProbeRedisAsync(stream, issues).ConfigureAwait(false);
                        risk = issues.Count > 0 ? Severity.Critical : Severity.Medium;
                        break;
                    case MessagingService.DefaultPort:
                        banner = await ProbeHyperLanAsync(stream).ConfigureAwait(false);
                        break;
                    default:
                        banner = await ReadBannerAsync(stream, 900).ConfigureAwait(false);
                        if (banner.StartsWith("SSH-1.", StringComparison.Ordinal))
                        {
                            issues.Add(Localization.Pick("SSH phiên bản 1 — đã bị phá, phải nâng cấp", "SSH protocol 1 — broken, upgrade now"));
                            risk = Severity.Critical;
                        }
                        break;
                }
            }
            catch { }
            return new ServiceFinding(p.Port, p.Service, risk, banner, issues);
        }

        private static async Task<string> ReadBannerAsync(NetworkStream s, int timeoutMs)
        {
            var buf = new byte[512];
            using var cts = new CancellationTokenSource(timeoutMs);
            try
            {
                int n = await s.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                return Printable(buf, n);
            }
            catch { return ""; }
        }

        private static string Printable(byte[] buf, int n)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < n && sb.Length < 120; i++)
            {
                char c = (char)buf[i];
                if (c is '\r' or '\n') { if (sb.Length > 0 && sb[^1] != ' ') sb.Append(' '); }
                else if (c >= 32 && c < 127) sb.Append(c);
            }
            return sb.ToString().Trim();
        }

        private static async Task<string> ProbeHttpAsync(NetworkStream s, IPAddress ip, List<string> issues)
        {
            byte[] req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: HyperLAN-Audit\r\n\r\n");
            await s.WriteAsync(req).ConfigureAwait(false);
            var buf = new byte[4096];
            int total = 0;
            using var cts = new CancellationTokenSource(1500);
            try
            {
                int n;
                while (total < buf.Length && (n = await s.ReadAsync(buf.AsMemory(total), cts.Token).ConfigureAwait(false)) > 0)
                    total += n;
            }
            catch { }
            string head = Encoding.ASCII.GetString(buf, 0, total);
            string status = head.Split('\n').FirstOrDefault()?.Trim() ?? "";
            string? server = head.Split('\n').Select(l => l.Trim())
                                 .FirstOrDefault(l => l.StartsWith("Server:", StringComparison.OrdinalIgnoreCase));
            if (head.Contains("WWW-Authenticate: Basic", StringComparison.OrdinalIgnoreCase))
                issues.Add(Localization.Pick("Đăng nhập Basic-Auth qua HTTP rõ — mật khẩu chỉ là base64, ai nghe lén cũng đọc được",
                                             "Basic-Auth login over plain HTTP — password is just base64, readable by any sniffer"));
            return string.Join("  ·  ", new[] { status, server }.Where(x => !string.IsNullOrEmpty(x)));
        }

        private static async Task<string> ProbeTlsAsync(NetworkStream s, IPAddress ip, List<string> issues)
        {
            X509Certificate2? cert = null;
            SslPolicyErrors errors = SslPolicyErrors.None;
            using var ssl = new SslStream(s, leaveInnerStreamOpen: true, (_, c, _, e) =>
            {
                if (c is not null) cert = new X509Certificate2(c);
                errors = e;
                return true; // KHÔNG tin — chỉ thu thập để phân tích
            });
            using var cts = new CancellationTokenSource(2500);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = ip.ToString(),
                EnabledSslProtocols = SslProtocols.None, // để OS chọn giao thức tốt nhất hai bên cùng hỗ trợ
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token).ConfigureAwait(false);

            string proto = ssl.SslProtocol switch
            {
                SslProtocols.Tls13 => "TLS 1.3",
                SslProtocols.Tls12 => "TLS 1.2",
#pragma warning disable SYSLIB0039
                SslProtocols.Tls11 => "TLS 1.1",
                SslProtocols.Tls => "TLS 1.0",
#pragma warning restore SYSLIB0039
                _ => ssl.SslProtocol.ToString(),
            };
            if (proto is "TLS 1.0" or "TLS 1.1")
                issues.Add(Localization.Pick($"Giao thức lỗi thời {proto} (BEAST/POODLE-era)", $"Obsolete protocol {proto}"));

            string cipher = "";
            try { cipher = ssl.NegotiatedCipherSuite.ToString(); } catch { }

            if (cert is null) return $"{proto} · {cipher}";
            string subject = cert.GetNameInfo(X509NameType.SimpleName, false);
            if (cert.NotAfter < DateTime.Now)
                issues.Add(Localization.Pick($"Chứng chỉ ĐÃ HẾT HẠN từ {cert.NotAfter:yyyy-MM-dd}", $"Certificate EXPIRED on {cert.NotAfter:yyyy-MM-dd}"));
            else if (cert.NotAfter < DateTime.Now.AddDays(30))
                issues.Add(Localization.Pick($"Chứng chỉ sắp hết hạn ({cert.NotAfter:yyyy-MM-dd})", $"Certificate expires soon ({cert.NotAfter:yyyy-MM-dd})"));
            if (cert.Subject == cert.Issuer)
                issues.Add(Localization.Pick("Chứng chỉ tự ký — trình duyệt không thể phân biệt với kẻ MITM", "Self-signed certificate — indistinguishable from a MITM to clients"));
            else if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
                issues.Add(Localization.Pick("Chuỗi chứng chỉ không tin cậy", "Untrusted certificate chain"));
            if (cert.PublicKey.Oid.FriendlyName == "RSA" && cert.PublicKey.GetRSAPublicKey()?.KeySize < 2048)
                issues.Add(Localization.Pick("Khóa RSA < 2048 bit", "RSA key < 2048 bits"));
            return $"{proto} · {cipher} · CN={subject} · exp {cert.NotAfter:yyyy-MM-dd}";
        }

        private static async Task<string> ProbeRedisAsync(NetworkStream s, List<string> issues)
        {
            await s.WriteAsync("PING\r\n"u8.ToArray()).ConfigureAwait(false);
            string reply = await ReadBannerAsync(s, 1000).ConfigureAwait(false);
            if (reply.StartsWith("+PONG", StringComparison.Ordinal))
                issues.Add(Localization.Pick("Redis trả lời lệnh KHÔNG cần mật khẩu — đọc/ghi toàn bộ dữ liệu được",
                                             "Redis answers commands WITHOUT a password — full read/write access"));
            return reply;
        }

        /// <summary>Peer Hyper-LAN gửi Hello ngay khi kết nối → đọc được tên + fingerprint (thông tin công khai).</summary>
        private static async Task<string> ProbeHyperLanAsync(NetworkStream s)
        {
            var header = new byte[Protocol.HeaderSize];
            using var cts = new CancellationTokenSource(1500);
            try
            {
                await s.ReadExactlyAsync(header, cts.Token).ConfigureAwait(false);
                if (header[0] != (byte)RecordType.Hello) return "";
                int len = BitConverter.ToInt32(header, 1);
                if (len <= 0 || len > Protocol.MaxHelloSize) return "";
                var body = new byte[len];
                await s.ReadExactlyAsync(body, cts.Token).ConfigureAwait(false);
                using var doc = JsonDocument.Parse(body);
                string name = doc.RootElement.GetProperty("Name").GetString() ?? "?";
                byte[] id = doc.RootElement.GetProperty("Id").GetBytesFromBase64();
                return $"Hyper-LAN v{doc.RootElement.GetProperty("V").GetInt32()} · {name} · {CryptoService.ComputeFingerprint(id)}";
            }
            catch { return "Hyper-LAN?"; }
        }
    }
}
