using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace networkApp.Security
{
    public sealed record AuditFinding(Severity Severity, string Title, string Detail);

    public sealed record WifiInfo(string Ssid, string Authentication, string Cipher, string Signal, string Band);

    public sealed record HostAuditReport(
        DateTime Time,
        IReadOnlyList<AuditFinding> Findings,
        IReadOnlyList<ListeningSocket> Listeners,
        IReadOnlyDictionary<string, bool?> Firewall,     // Domain / Private / Public → bật?
        IReadOnlyList<(string Name, string Category)> Networks,
        WifiInfo? Wifi)
    {
        /// <summary>Điểm 0–100: trừ theo mức độ nghiêm trọng của từng phát hiện.</summary>
        public int Score => Math.Max(0, 100 - Findings.Sum(f => f.Severity switch
        {
            Severity.Critical => 30, Severity.High => 15, Severity.Medium => 7, Severity.Low => 2, _ => 0,
        }));
    }

    /// <summary>
    /// Tự kiểm định MÁY NÀY — "bề mặt tấn công" nhìn từ trong LAN:
    ///  • Mọi cổng TCP/UDP đang lắng nghe + tiến trình sở hữu (iphlpapi), đánh dấu cổng nguy hiểm lộ ra ngoài.
    ///  • Windows Firewall theo từng profile (Domain/Private/Public) — đọc registry, không cần admin.
    ///  • Loại mạng đang kết nối (Public/Private) qua COM NetworkListManager.
    ///  • Bảo mật Wi-Fi đang dùng: Open / WEP / WPA-TKIP / WPA2 / WPA3 (netsh wlan).
    /// </summary>
    public static class HostAudit
    {
        public static HostAuditReport Run()
        {
            var findings = new List<AuditFinding>();

            // ---------- Firewall ----------
            var fw = new Dictionary<string, bool?>
            {
                ["Domain"] = FirewallEnabled("DomainProfile"),
                ["Private"] = FirewallEnabled("StandardProfile"),
                ["Public"] = FirewallEnabled("PublicProfile"),
            };
            foreach (var (profile, on) in fw)
                if (on == false)
                    findings.Add(new AuditFinding(profile == "Public" ? Severity.Critical : Severity.High,
                        Localization.Pick($"Windows Firewall TẮT ở profile {profile}", $"Windows Firewall is OFF for the {profile} profile"),
                        Localization.Pick("Mọi dịch vụ đang lắng nghe đều lộ cho cả mạng. Bật lại trong Windows Security → Firewall.",
                                          "Every listening service is reachable by the whole network. Re-enable it in Windows Security → Firewall.")));

            // ---------- Loại mạng ----------
            var networks = ConnectedNetworks();
            foreach (var (name, cat) in networks)
                if (cat == "Private" && name.Contains("Free", StringComparison.OrdinalIgnoreCase) ||
                    cat == "Private" && name.Contains("Guest", StringComparison.OrdinalIgnoreCase) ||
                    cat == "Private" && name.Contains("Cafe", StringComparison.OrdinalIgnoreCase))
                    findings.Add(new AuditFinding(Severity.Medium,
                        Localization.Pick($"Mạng \"{name}\" đang được tin cậy (Private)", $"Network \"{name}\" is trusted (Private)"),
                        Localization.Pick("Tên mạng giống Wi-Fi công cộng — nên đặt Public để Windows chặn chia sẻ/khám phá.",
                                          "Looks like public Wi-Fi — set it to Public so Windows blocks sharing/discovery.")));

            // ---------- Wi-Fi ----------
            var wifi = WifiStatus();
            if (wifi is not null)
            {
                string a = wifi.Authentication.ToUpperInvariant(), c = wifi.Cipher.ToUpperInvariant();
                if (a.Contains("OPEN") || c == "NONE")
                    findings.Add(new AuditFinding(Severity.Critical,
                        Localization.Pick($"Wi-Fi \"{wifi.Ssid}\" KHÔNG mã hóa", $"Wi-Fi \"{wifi.Ssid}\" is UNENCRYPTED"),
                        Localization.Pick("Ai trong tầm sóng cũng bắt được gói tin của bạn. App này vẫn an toàn nhờ E2E, nhưng các ứng dụng khác thì không.",
                                          "Anyone in range can capture your packets. This app stays safe thanks to E2E — other apps may not.")));
                else if (c.Contains("WEP") || a.Contains("WEP"))
                    findings.Add(new AuditFinding(Severity.Critical, "WEP",
                        Localization.Pick("WEP bị bẻ trong vài phút (tấn công FMS/PTW). Đổi sang WPA2/WPA3.", "WEP is crackable in minutes (FMS/PTW). Switch to WPA2/WPA3.")));
                else if (c.Contains("TKIP"))
                    findings.Add(new AuditFinding(Severity.High, "WPA-TKIP",
                        Localization.Pick("TKIP đã lỗi thời — đặt router dùng AES/CCMP.", "TKIP is deprecated — configure the router for AES/CCMP.")));
                else if (a.Contains("WPA2") && !a.Contains("WPA3"))
                    findings.Add(new AuditFinding(Severity.Low, "WPA2",
                        Localization.Pick("WPA2-PSK dễ bị dò mật khẩu offline nếu mật khẩu yếu (bắt handshake). WPA3-SAE chống được.",
                                          "WPA2-PSK allows offline password cracking from a captured handshake if the password is weak. WPA3-SAE prevents it.")));
            }

            // ---------- Cổng đang lắng nghe ----------
            var listeners = NetNative.GetListeners();
            var exposedTcp = listeners.Where(l => l.Protocol.StartsWith("TCP") && l.IsExposed)
                                      .GroupBy(l => l.Port).Select(g => g.First()).ToList();
            foreach (var l in exposedTcp)
            {
                var info = Knowledge.Describe(l.Port);
                if (info.Service == "?" || info.Risk < Severity.Medium) continue;
                bool fwOn = fw.Values.All(v => v != false);
                var sev = fwOn ? (Severity)Math.Max((int)Severity.Low, (int)info.Risk - 1) : info.Risk; // firewall bật → giảm 1 bậc
                findings.Add(new AuditFinding(sev,
                    Localization.Pick($"Máy này mở {info.Service} (TCP {l.Port}) cho cả mạng", $"This machine exposes {info.Service} (TCP {l.Port})"),
                    $"{l.ProcessName} (PID {l.Pid}) · {Localization.Pick(info.WhyVi, info.WhyEn)}"));
            }

            findings.Sort((x, y) => y.Severity.CompareTo(x.Severity));
            return new HostAuditReport(DateTime.Now, findings, listeners, fw, networks, wifi);
        }

        private static bool? FirewallEnabled(string profileKey)
        {
            // Group Policy (nếu có) được ưu tiên hơn cấu hình local
            string[] paths =
            {
                $@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{profileKey}",
                $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{profileKey}",
            };
            foreach (var p in paths)
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(p);
                    if (k?.GetValue("EnableFirewall") is int v) return v != 0;
                }
                catch { }
            }
            return null;
        }

        /// <summary>COM INetworkListManager — cùng nguồn với "Network & Internet" trong Settings.</summary>
        private static List<(string, string)> ConnectedNetworks()
        {
            var list = new List<(string, string)>();
            try
            {
                Type? t = Type.GetTypeFromCLSID(new Guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B"));
                if (t is null) return list;
                dynamic nlm = Activator.CreateInstance(t)!;
                foreach (dynamic net in nlm.GetNetworks(1 /* NLM_ENUM_NETWORK_CONNECTED */))
                {
                    int cat = net.GetCategory();
                    list.Add(((string)net.GetName(), cat switch { 0 => "Public", 1 => "Private", 2 => "Domain", _ => "?" }));
                }
            }
            catch (Exception ex) { Debug.WriteLine($"[NLM] {ex.Message}"); }
            return list;
        }

        /// <summary>Đọc `netsh wlan show interfaces`. Nhận dạng theo GIÁ TRỊ (WPA2, CCMP...) để chạy được trên Windows đa ngôn ngữ.</summary>
        private static WifiInfo? WifiStatus()
        {
            try
            {
                var psi = new ProcessStartInfo("netsh", "wlan show interfaces")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
                    StandardOutputEncoding = System.Text.Encoding.UTF8,
                };
                using var p = Process.Start(psi)!;
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(3000);

                var values = output.Split('\n')
                    .Select(l => l.Split(new[] { ':' }, 2))
                    .Where(kv => kv.Length == 2)
                    .Select(kv => (Key: kv[0].Trim(), Value: kv[1].Trim()))
                    .ToList();
                if (values.Count == 0) return null;

                string ssid = values.FirstOrDefault(v => v.Key == "SSID").Value ?? "";
                string auth = values.Select(v => v.Value).FirstOrDefault(v =>
                    Regex.IsMatch(v, @"^(WPA3|WPA2|WPA|Open|Shared|WEP|OWE)", RegexOptions.IgnoreCase)) ?? "";
                string cipher = values.Select(v => v.Value).FirstOrDefault(v =>
                    Regex.IsMatch(v, @"^(CCMP|GCMP|TKIP|WEP|None)", RegexOptions.IgnoreCase)) ?? "";
                string signal = values.Select(v => v.Value).FirstOrDefault(v => Regex.IsMatch(v, @"^\d{1,3}%$")) ?? "";
                string band = values.Select(v => v.Value).FirstOrDefault(v => Regex.IsMatch(v, @"^\d(\.\d)? GHz$")) ?? "";
                if (auth.Length == 0 && ssid.Length == 0) return null; // không có Wi-Fi / chưa cấp quyền vị trí
                return new WifiInfo(ssid, auth, cipher, signal, band);
            }
            catch { return null; }
        }
    }
}
