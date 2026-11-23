using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace networkApp.Security
{
    public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

    /// <summary>Một dịch vụ mạng phổ biến + mức rủi ro khi nó MỞ trong LAN + khuyến nghị khắc phục.</summary>
    public sealed record PortInfo(int Port, string Service, Severity Risk, string WhyVi, string WhyEn);

    public static class Knowledge
    {
        /// <summary>
        /// Danh mục cổng kiểm định — chọn theo các dịch vụ hay bị khai thác trong mạng nội bộ
        /// (tham khảo CIS Controls, các bài học từ WannaCry/SMB, Mirai/Telnet, Redis/Mongo không mật khẩu).
        /// </summary>
        public static readonly IReadOnlyList<PortInfo> Ports = new List<PortInfo>
        {
            new(21, "FTP", Severity.High, "FTP truyền mật khẩu dạng rõ. Thay bằng SFTP/FTPS.", "FTP sends credentials in cleartext. Use SFTP/FTPS instead."),
            new(22, "SSH", Severity.Low, "SSH an toàn nếu tắt đăng nhập mật khẩu, dùng khóa.", "SSH is fine with key-only auth; disable password login."),
            new(23, "Telnet", Severity.Critical, "Telnet không mã hóa — mục tiêu số 1 của botnet (Mirai). Tắt ngay.", "Telnet is unencrypted — botnet target #1 (Mirai). Disable it."),
            new(25, "SMTP", Severity.Medium, "Máy chủ mail trong LAN — kiểm tra open relay.", "Mail server on the LAN — check for open relay."),
            new(53, "DNS", Severity.Low, "DNS nội bộ — đảm bảo không phải open resolver.", "Internal DNS — make sure it is not an open resolver."),
            new(80, "HTTP", Severity.Medium, "Web không mã hóa (thường là trang quản trị router/camera) — mật khẩu đi dạng rõ.", "Unencrypted web (often router/camera admin) — passwords travel in clear."),
            new(110, "POP3", Severity.Medium, "POP3 không mã hóa.", "Unencrypted POP3."),
            new(135, "MS-RPC", Severity.Medium, "RPC của Windows — không nên lộ ngoài mạng tin cậy.", "Windows RPC — should not be exposed beyond trusted networks."),
            new(139, "NetBIOS", Severity.High, "NetBIOS/SMB cũ — dò tên máy, chia sẻ file.", "Legacy NetBIOS/SMB — name and share enumeration."),
            new(143, "IMAP", Severity.Medium, "IMAP không mã hóa.", "Unencrypted IMAP."),
            new(443, "HTTPS", Severity.Info, "Web có TLS — kiểm tra chứng chỉ bên dưới.", "TLS web — see certificate check."),
            new(445, "SMB", Severity.High, "Chia sẻ file Windows — đường lây của WannaCry/NotPetya. Chỉ mở khi cần, tắt SMBv1.", "Windows file sharing — WannaCry/NotPetya vector. Open only if needed; disable SMBv1."),
            new(554, "RTSP", Severity.Medium, "Luồng camera IP — hay để mật khẩu mặc định.", "IP camera stream — often default credentials."),
            new(1433, "MSSQL", Severity.High, "CSDL lộ trong LAN — chỉ cho máy ứng dụng truy cập.", "Database exposed on the LAN — restrict to app servers."),
            new(1883, "MQTT", Severity.High, "Broker IoT, thường không xác thực.", "IoT broker, frequently unauthenticated."),
            new(2049, "NFS", Severity.High, "Chia sẻ NFS — kiểm tra export.", "NFS share — review exports."),
            new(3306, "MySQL", Severity.High, "CSDL lộ trong LAN.", "Database exposed on the LAN."),
            new(3389, "RDP", Severity.High, "Remote Desktop — mục tiêu dò mật khẩu & ransomware. Bật NLA, giới hạn IP.", "Remote Desktop — brute-force & ransomware target. Enforce NLA, restrict IPs."),
            new(5000, "UPnP/HTTP", Severity.Low, "Dịch vụ HTTP/UPnP phụ.", "Auxiliary HTTP/UPnP service."),
            new(5432, "PostgreSQL", Severity.High, "CSDL lộ trong LAN.", "Database exposed on the LAN."),
            new(5900, "VNC", Severity.High, "VNC thường mã hóa yếu/mật khẩu 8 ký tự.", "VNC often has weak/8-char passwords and weak crypto."),
            new(5985, "WinRM", Severity.Medium, "Quản trị từ xa PowerShell (HTTP).", "PowerShell remoting over HTTP."),
            new(6379, "Redis", Severity.Critical, "Redis mặc định KHÔNG mật khẩu — ai cũng đọc/ghi được, có thể chiếm máy.", "Redis has NO auth by default — anyone can read/write, even take over the host."),
            new(7547, "TR-069", Severity.High, "Giao thức quản lý router từ nhà mạng — từng bị khai thác hàng loạt.", "ISP router management — historically mass-exploited."),
            new(8080, "HTTP-alt", Severity.Medium, "Web phụ/proxy không mã hóa.", "Auxiliary web/proxy without TLS."),
            new(8443, "HTTPS-alt", Severity.Info, "Web phụ có TLS.", "Auxiliary TLS web."),
            new(MessagingService.DefaultPort, "Hyper-LAN", Severity.Info, "Hyper-LAN Commander — kênh mã hóa đầu-cuối (an toàn).", "Hyper-LAN Commander — end-to-end encrypted (safe)."),
            new(9100, "JetDirect", Severity.Medium, "Máy in raw — có thể in/đọc tùy ý.", "Raw printing — arbitrary print jobs."),
            new(9200, "Elasticsearch", Severity.High, "Elasticsearch thường không xác thực.", "Elasticsearch is often unauthenticated."),
            new(11211, "Memcached", Severity.High, "Memcached không xác thực.", "Memcached has no auth."),
            new(27017, "MongoDB", Severity.High, "MongoDB cũ mặc định không mật khẩu.", "Older MongoDB has no auth by default."),
        };

        private static readonly Dictionary<int, PortInfo> ByPort = Ports.ToDictionary(p => p.Port);

        public static PortInfo Describe(int port) => ByPort.TryGetValue(port, out var p) ? p
            : new PortInfo(port, "?", Severity.Low, "Dịch vụ không xác định.", "Unknown service.");

        // ================= Nhà sản xuất từ OUI (3 byte đầu MAC) =================
        // Bảng rút gọn các hãng hay gặp trong LAN gia đình/văn phòng (nguồn: IEEE OUI registry).
        private static readonly Dictionary<string, string> Oui = new(StringComparer.OrdinalIgnoreCase)
        {
            ["00-50-56"] = "VMware", ["00-0C-29"] = "VMware", ["00-05-69"] = "VMware",
            ["08-00-27"] = "VirtualBox", ["0A-00-27"] = "VirtualBox (host-only)",
            ["00-15-5D"] = "Microsoft Hyper-V", ["00-1C-42"] = "Parallels",
            ["B8-27-EB"] = "Raspberry Pi", ["DC-A6-32"] = "Raspberry Pi", ["E4-5F-01"] = "Raspberry Pi", ["D8-3A-DD"] = "Raspberry Pi",
            ["F0-18-98"] = "Apple", ["3C-22-FB"] = "Apple", ["A4-83-E7"] = "Apple", ["AC-BC-32"] = "Apple", ["F4-0F-24"] = "Apple", ["8C-85-90"] = "Apple",
            ["00-1A-11"] = "Google", ["F4-F5-D8"] = "Google", ["3C-5A-B4"] = "Google",
            ["FC-A6-67"] = "Amazon", ["44-65-0D"] = "Amazon",
            ["8C-79-F5"] = "Samsung", ["5C-0A-5B"] = "Samsung", ["F8-04-2E"] = "Samsung",
            ["64-09-80"] = "Xiaomi", ["28-6C-07"] = "Xiaomi", ["50-64-2B"] = "Xiaomi",
            ["00-E0-FC"] = "Huawei", ["48-46-FB"] = "Huawei", ["E0-24-7F"] = "Huawei",
            ["50-C7-BF"] = "TP-Link", ["98-DA-C4"] = "TP-Link", ["EC-08-6B"] = "TP-Link", ["60-32-B1"] = "TP-Link", ["14-EB-B6"] = "TP-Link",
            ["00-1D-0F"] = "TP-Link", ["C0-06-C3"] = "TP-Link",
            ["00-14-6C"] = "Netgear", ["A0-40-A0"] = "Netgear",
            ["04-D9-F5"] = "ASUS", ["2C-56-DC"] = "ASUS", ["AC-22-0B"] = "ASUS",
            ["00-1B-21"] = "Intel", ["3C-97-0E"] = "Intel", ["8C-8D-28"] = "Intel", ["A4-4C-C8"] = "Intel", ["F8-63-3F"] = "Intel",
            ["00-14-22"] = "Dell", ["F8-BC-12"] = "Dell", ["B0-83-FE"] = "Dell",
            ["3C-D9-2B"] = "HP", ["9C-8E-99"] = "HP", ["00-1E-0B"] = "HP",
            ["00-1B-63"] = "Apple", ["00-25-00"] = "Apple",
            ["00-0F-66"] = "Cisco-Linksys", ["00-1A-A1"] = "Cisco", ["00-40-96"] = "Cisco",
            ["74-83-C2"] = "Ubiquiti", ["24-5A-4C"] = "Ubiquiti", ["FC-EC-DA"] = "Ubiquiti",
            ["4C-ED-FB"] = "ASUS", ["E8-48-B8"] = "Samsung",
            ["BC-5F-F4"] = "ASRock", ["70-85-C2"] = "ASRock",
            ["00-E0-4C"] = "Realtek", ["52-54-00"] = "QEMU/KVM",
            ["18-FE-34"] = "Espressif (IoT)", ["24-0A-C4"] = "Espressif (IoT)", ["A4-CF-12"] = "Espressif (IoT)", ["84-F3-EB"] = "Espressif (IoT)",
            ["00-17-88"] = "Philips Hue", ["D0-73-D5"] = "LIFX",
            ["C8-3A-35"] = "Tenda", ["00-90-4C"] = "Epson", ["00-80-77"] = "Brother", ["00-00-48"] = "Epson",
            ["A8-6B-AD"] = "Hikvision", ["C0-56-E3"] = "Hikvision", ["4C-11-BF"] = "Dahua", ["3C-EF-8C"] = "Dahua",
            ["00-D0-2D"] = "Ezviz",
        };

        public static string Vendor(string mac)
        {
            if (string.IsNullOrEmpty(mac) || mac.Length < 8) return "";
            if (IsRandomizedMac(mac)) return Localization.Pick("MAC ngẫu nhiên (riêng tư)", "Randomized MAC (private)");
            return Oui.TryGetValue(mac[..8], out var v) ? v : "";
        }

        /// <summary>
        /// Bit "locally administered" (bit 1 của byte đầu) = MAC do phần mềm đặt — điện thoại
        /// iOS/Android/Windows bật "Private Wi-Fi address" sẽ có dạng này.
        /// </summary>
        public static bool IsRandomizedMac(string mac)
            => mac.Length >= 2 && byte.TryParse(mac[..2], System.Globalization.NumberStyles.HexNumber, null, out byte b)
               && (b & 0x02) != 0 && (b & 0x01) == 0;

        public static bool IsMulticastOrBroadcastMac(string mac)
            => mac.StartsWith("FF-FF-FF", StringComparison.OrdinalIgnoreCase) ||
               mac.StartsWith("01-00-5E", StringComparison.OrdinalIgnoreCase) ||
               mac.StartsWith("33-33", StringComparison.OrdinalIgnoreCase);

        // ================= Phạm vi địa chỉ được phép kiểm định =================

        /// <summary>Chỉ cho quét dải private (RFC 1918), link-local (RFC 3927) và loopback.</summary>
        public static bool IsAuditable(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = ip.GetAddressBytes();
            return b[0] == 10 || b[0] == 127 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }

        public static uint ToUInt(IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
        }

        public static IPAddress FromUInt(uint v) =>
            new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

        public static string SeverityLabel(Severity s) => s switch
        {
            Severity.Critical => Localization.Pick("NGHIÊM TRỌNG", "CRITICAL"),
            Severity.High => Localization.Pick("CAO", "HIGH"),
            Severity.Medium => Localization.Pick("TRUNG BÌNH", "MEDIUM"),
            Severity.Low => Localization.Pick("THẤP", "LOW"),
            _ => Localization.Pick("THÔNG TIN", "INFO"),
        };
    }
}
