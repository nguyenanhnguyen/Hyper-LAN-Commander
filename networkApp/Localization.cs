using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace networkApp
{
    /// <summary>
    /// Song ngữ EN/VI theo cơ chế DynamicResource của WPF:
    /// - Mọi chuỗi UI nằm ở đây, bơm vào Application.Resources.
    /// - Label trong XAML dùng {DynamicResource key} → đổi ngôn ngữ là TỰ CẬP NHẬT ngay.
    /// - Chuỗi động trong code lấy qua Localization.T(key) + string.Format.
    /// - Lựa chọn được lưu ở %AppData%\HyperLAN\lang.cfg cho lần mở sau.
    /// </summary>
    public static class Localization
    {
        public const string VI = "vi";
        public const string EN = "en";
        public static string Current { get; private set; } = VI;

        private static readonly string ConfigPath = Path.Combine(AppProfile.RootDataDir, "lang.cfg");

        // key → (tiếng Việt, English)
        private static readonly Dictionary<string, (string vi, string en)> Strings = new()
        {
            // Nút chuyển ngôn ngữ hiển thị NGÔN NGỮ SẼ CHUYỂN SANG
            ["L_LangToggle"] = ("EN", "VI"),

            // ---- Sidebar ----
            ["L_Tagline"] = ("Mạng LAN mã hóa đầu-cuối", "End-to-end encrypted LAN"),
            ["L_YourIdentity"] = ("DANH TÍNH CỦA BẠN", "YOUR IDENTITY"),
            ["L_CopyId"] = ("Sao chép fingerprint", "Copy fingerprint"),
            ["L_Copied"] = ("Đã sao chép fingerprint", "Fingerprint copied"),
            ["L_Devices"] = ("THIẾT BỊ", "DEVICES"),
            ["L_OnlineCount"] = ("{0} online", "{0} online"),
            ["L_Scan"] = ("Quét mạng", "Scan network"),
            ["L_Connect"] = ("Kết nối", "Connect"),
            ["L_ManualHint"] = ("IP hoặc IP:port", "IP or IP:port"),
            ["L_ManualTooltip"] = ("Kết nối thủ công khi discovery bị chặn (vd: mạng công ty, khác subnet).",
                                   "Connect manually when discovery is blocked (e.g. corporate network, different subnet)."),
            ["L_OpenDownloads"] = ("Mở thư mục nhận file", "Open received files folder"),
            ["L_InterfacesTip"] = ("Các card mạng đang phát discovery:", "Network interfaces used for discovery:"),
            ["L_FpTooltip"] = ("Danh tính mật mã của máy này — không thể giả mạo. Đọc cho bạn bè để họ đối chiếu.",
                               "This machine's cryptographic identity — cannot be forged. Read it aloud so peers can verify."),
            ["L_StSecure"] = ("Phiên mã hóa", "Secure session"),
            ["L_StOnline"] = ("Online", "Online"),
            ["L_StOffline"] = ("Offline", "Offline"),
            ["L_BadgeNew"] = ("MỚI", "NEW"),
            ["L_BadgeVerified"] = ("✓ ĐÃ XÁC MINH", "✓ VERIFIED"),
            ["L_NoDevices"] = ("Chưa thấy thiết bị nào.\nMở Hyper-LAN trên máy khác cùng mạng — nó sẽ tự xuất hiện ở đây.",
                               "No devices yet.\nRun Hyper-LAN on another machine on this network — it will appear here automatically."),

            // ---- Chat ----
            ["L_ChatEmptyTitle"] = ("Chọn một thiết bị để bắt đầu", "Pick a device to get started"),
            ["L_ChatEmptyBody"] = ("Tin nhắn và file được mã hóa đầu-cuối bằng AES-256-GCM.\nKhóa phiên dẫn xuất từ ECDH tạm thời — không bao giờ đi qua mạng.",
                                   "Messages and files are end-to-end encrypted with AES-256-GCM.\nSession keys come from ephemeral ECDH — they never cross the network."),
            ["L_Feat1"] = ("🔍  Tự phát hiện máy trong LAN (broadcast + multicast trên mọi card mạng)",
                           "🔍  Zero-config discovery (broadcast + multicast on every interface)"),
            ["L_Feat2"] = ("🔐  ECDHE P-256 + ECDSA + AES-256-GCM, Perfect Forward Secrecy",
                           "🔐  ECDHE P-256 + ECDSA + AES-256-GCM, Perfect Forward Secrecy"),
            ["L_Feat3"] = ("⏯  Truyền file tự resume khi rớt mạng, kiểm SHA-256 đầu-cuối",
                           "⏯  File transfers auto-resume after drops, end-to-end SHA-256 check"),
            ["L_Feat4"] = ("🖱  Kéo-thả file vào đây (hoặc Ctrl+V) để gửi", "🖱  Drag & drop (or Ctrl+V) files here to send"),
            ["L_InputHint"] = ("Nhập tin nhắn… (Enter để gửi, Shift+Enter xuống dòng)",
                               "Type a message… (Enter to send, Shift+Enter for a new line)"),
            ["L_Send"] = ("Gửi", "Send"),
            ["L_FileTooltip"] = ("Gửi file (bên kia sẽ được hỏi trước khi nhận)",
                                 "Send files (the receiver is asked before accepting)"),
            ["L_DropHere"] = ("Thả để gửi file", "Drop to send"),
            ["L_SecureSub"] = ("🔒 Mã hóa đầu-cuối · ECDHE-P256 · AES-256-GCM · PFS · phiên {0}",
                               "🔒 End-to-end encrypted · ECDHE-P256 · AES-256-GCM · PFS · session {0}"),
            ["L_OnlineSub"] = ("Online — phiên mã hóa sẽ được thiết lập khi bạn gửi",
                               "Online — an encrypted session is set up when you send"),
            ["L_OfflineSub"] = ("Offline — tin nhắn sẽ được gửi khi kết nối lại được",
                                "Offline — will try to reach it when you send"),
            ["L_SafetyBtn"] = ("Safety number", "Safety number"),
            ["L_SafetyTitle"] = ("Xác minh danh tính (chống kẻ đứng giữa)", "Verify identity (defeats man-in-the-middle)"),
            ["L_SafetyBody"] = ("So dãy số này với màn hình của bên kia (gặp mặt hoặc gọi điện). Hai bên giống hệt nhau = không có ai chen giữa.",
                                "Compare these digits with the other screen (in person or by phone). Identical on both sides = nobody is in the middle."),
            ["L_SafetyNone"] = ("Cần kết nối với peer ít nhất một lần để có safety number.",
                                "Connect to this peer at least once to get a safety number."),
            ["L_MarkVerified"] = ("Đánh dấu đã xác minh", "Mark as verified"),
            ["L_Unverify"] = ("Bỏ xác minh", "Remove verification"),
            ["L_You"] = ("Bạn", "You"),

            // ---- Trạng thái / thông báo ----
            ["L_StatusReady"] = ("Sẵn sàng", "Ready"),
            ["L_Scanning"] = ("Đang quét mạng…", "Scanning…"),
            ["L_ScanDone"] = ("Quét xong: {0} thiết bị online", "Scan complete: {0} device(s) online"),
            ["L_ScanNone"] = ("Không thấy thiết bị nào — kiểm tra firewall (cho phép mạng Private) hoặc AP isolation của Wi-Fi",
                              "No devices found — check the firewall (allow Private networks) or Wi-Fi client isolation"),
            ["L_ScanError"] = ("Lỗi quét: {0}", "Scan error: {0}"),
            ["L_Seen"] = ("Phát hiện: {0}", "Discovered: {0}"),
            ["L_PeerLeft"] = ("{0} đã rời mạng", "{0} left the network"),
            ["L_Connecting"] = ("Đang kết nối {0}…", "Connecting to {0}…"),
            ["L_Verified"] = ("🔒 Phiên mã hóa với {0} ({1})", "🔒 Secure session with {0} ({1})"),
            ["L_SessionLost"] = ("Mất phiên với {0}", "Session with {0} closed"),
            ["L_ConnectFail"] = ("Kết nối thất bại: {0}", "Connection failed: {0}"),
            ["L_SelfConnect"] = ("Đó là chính máy này", "That's this machine"),
            ["L_SelectFirst"] = ("Hãy chọn một thiết bị trước", "Select a device first"),
            ["L_SendFail"] = ("Gửi thất bại: {0}", "Send failed: {0}"),
            ["L_Unknown"] = ("(chưa rõ tên)", "(unknown)"),
            ["L_NetChanged"] = ("Mạng thay đổi — đã dò lại card mạng và thông báo lại", "Network changed — interfaces re-scanned and re-announced"),
            ["L_Rejected"] = ("Từ chối kết nối từ {0}: {1}", "Rejected connection from {0}: {1}"),
            ["L_TamperedChat"] = ("⚠ Kết nối bị đóng: một gói tin không qua được kiểm tra toàn vẹn AES-GCM (có thể bị sửa đổi trên đường truyền).",
                                  "⚠ Connection closed: a packet failed AES-GCM integrity check (possibly modified in transit)."),
            ["L_IncomingFile"] = ("{0} muốn gửi file {1}", "{0} wants to send {1}"),
            ["L_SkipFolder"] = ("Bỏ qua thư mục {0} (chỉ gửi được file)", "Skipped folder {0} (only files can be sent)"),
            ["L_ChooseFile"] = ("Chọn file để gửi", "Choose files to send"),
            ["L_Fatal"] = ("Lỗi không mong muốn", "Unexpected error"),

            // ---- Truyền file ----
            ["L_Accept"] = ("Nhận", "Accept"),
            ["L_Decline"] = ("Từ chối", "Decline"),
            ["L_Cancel"] = ("Hủy", "Cancel"),
            ["L_ShowFile"] = ("Mở thư mục", "Show in folder"),
            ["L_TrTo"] = ("gửi tới {0}", "to {0}"),
            ["L_TrFrom"] = ("từ {0}", "from {0}"),
            ["L_TrOffering"] = ("Đang chờ {0} đồng ý…", "Waiting for {0} to accept…"),
            ["L_TrAsk"] = ("Muốn gửi file này cho bạn", "Wants to send you this file"),
            ["L_OfferResume"] = (" — đã có {0}%, sẽ tải tiếp", " — {0}% already here, will resume"),
            ["L_TrPreparing"] = ("Đang kiểm tra phần đã nhận trước đó…", "Checking previously received data…"),
            ["L_ProgSend"] = ("Đang gửi", "Sending"),
            ["L_ProgRecv"] = ("Đang nhận", "Receiving"),
            ["L_TrResumedFrom"] = (" · tiếp tục từ {0}%", " · resumed from {0}%"),
            ["L_TrReconnecting"] = ("Mất kết nối — đang tự kết nối lại để tải tiếp (lần {0})…",
                                    "Connection lost — reconnecting to resume (attempt {0})…"),
            ["L_TrPaused"] = ("Tạm dừng — mất kết nối, sẽ tự tiếp tục khi bên gửi quay lại",
                              "Paused — connection lost, resumes automatically when the sender is back"),
            ["L_TrVerifying"] = ("Đang đối chiếu SHA-256…", "Verifying SHA-256…"),
            ["L_TrDelivered"] = ("✓ Đã giao — bên nhận xác nhận SHA-256 khớp", "✓ Delivered — receiver confirmed SHA-256"),
            ["L_TrReceived"] = ("✓ Đã nhận — SHA-256 khớp", "✓ Received — SHA-256 verified"),
            ["L_TrRejected"] = ("Đã bị từ chối", "Declined"),
            ["L_TrCanceled"] = ("Đã hủy (phần dở dang được giữ để tải tiếp)", "Canceled (partial data kept for resume)"),
            ["L_TrCanceledPeer"] = ("Bên kia đã hủy", "Canceled by the other side"),
            ["L_TrEta"] = ("còn {0}", "{0} left"),
            ["L_ErrTimeout"] = ("Bên nhận không phản hồi", "No response from receiver"),
            ["L_ErrIntegrity"] = ("✗ SHA-256 không khớp — dữ liệu hỏng đã bị loại bỏ", "✗ SHA-256 mismatch — corrupted data discarded"),
            ["L_ErrDiskFull"] = ("Ổ đĩa bên nhận không đủ chỗ", "Receiver's disk is full"),
            ["L_ErrPeerGone"] = ("Mất kết nối quá lâu — gửi lại để tải tiếp từ chỗ dừng", "Peer unreachable too long — resend to resume where it stopped"),
            ["L_ErrBusy"] = ("File này đang được nhận ở một transfer khác", "This file is already being received"),
            ["L_ErrIo"] = ("Lỗi: {0}", "Error: {0}"),
            ["L_SentStatus"] = ("Đã giao {0}", "Delivered {0}"),
            ["L_RecvStatus"] = ("Đã nhận {0}", "Received {0}"),

            // ---- Điều hướng ----
            ["N_Chat"] = ("Trò chuyện", "Chat"),
            ["N_Security"] = ("An ninh", "Security"),

            // ---- Security Center ----
            ["S_Title"] = ("Trung tâm An ninh Mạng", "Network Security Center"),
            ["S_Subtitle"] = ("Kiểm định LAN · giám sát tấn công · soi giao thức · tự tấn công chứng minh",
                              "LAN audit · threat monitoring · protocol inspection · self-attack proofs"),
            ["S_Export"] = ("Xuất báo cáo HTML", "Export HTML report"),
            ["S_TabOverview"] = ("Tổng quan", "Overview"),
            ["S_TabLan"] = ("Kiểm định LAN", "LAN Audit"),
            ["S_TabDevice"] = ("Máy này", "This Device"),
            ["S_TabInspector"] = ("Soi giao thức", "Protocol Inspector"),
            ["S_TabLab"] = ("Attack Lab", "Attack Lab"),
            ["S_TabTools"] = ("Công cụ", "Tools"),

            ["S_CardDevice"] = ("ĐIỂM MÁY NÀY", "DEVICE SCORE"),
            ["S_CardLan"] = ("THIẾT BỊ TRONG LAN", "LAN DEVICES"),
            ["S_CardMonitor"] = ("GIÁM SÁT ARP", "ARP MONITOR"),
            ["S_CardLab"] = ("ATTACK LAB", "ATTACK LAB"),
            ["S_CardProtocol"] = ("GIAO THỨC HLC2", "HLC2 PROTOCOL"),
            ["S_Events"] = ("Nhật ký sự kiện an ninh", "Security event log"),
            ["S_NoEvents"] = ("Chưa có sự kiện nào. Giám sát ARP chạy nền mỗi 4 giây.", "No events yet. The ARP monitor runs every 4 seconds."),
            ["S_NotRun"] = ("chưa chạy", "not run"),

            ["S_LanIntro"] = ("Quét không xâm nhập: ping sweep → bảng ARP → TCP connect scan các cổng hay bị khai thác → banner, chứng chỉ TLS, Redis không mật khẩu… Chỉ dải private, không thử mật khẩu.",
                              "Non-intrusive: ping sweep → ARP table → TCP connect scan of commonly abused ports → banners, TLS certificates, unauthenticated Redis… Private ranges only, no password guessing."),
            ["S_Interface"] = ("Card mạng", "Interface"),
            ["S_WholeSubnet"] = ("Cả subnet (tối đa /22)", "Whole subnet (max /22)"),
            ["S_Consent"] = ("Tôi sở hữu hoặc được phép kiểm định mạng này", "I own or am authorized to audit this network"),
            ["S_StartScan"] = ("Bắt đầu quét", "Start scan"),
            ["S_Stop"] = ("Dừng", "Stop"),
            ["S_NeedConsent"] = ("Hãy xác nhận bạn có quyền kiểm định mạng này.", "Please confirm you are authorized to audit this network."),

            ["S_DeviceIntro"] = ("Bề mặt tấn công của chính máy này: cổng đang lắng nghe + tiến trình, firewall, loại mạng, bảo mật Wi-Fi.",
                                 "This machine's attack surface: listening ports + processes, firewall, network profile, Wi-Fi security."),
            ["S_RunAudit"] = ("Kiểm tra lại", "Re-run audit"),
            ["S_Listeners"] = ("Cổng đang lắng nghe", "Listening sockets"),
            ["S_OnlyExposed"] = ("Chỉ hiện cổng lộ ra mạng", "Exposed only"),

            ["S_InspIntro"] = ("Mọi record HLC2 vào/ra máy này theo thời gian thực. Bật \"Góc nhìn kẻ nghe lén\" để thấy đúng những gì Wireshark thấy.",
                               "Every HLC2 record entering/leaving this machine, live. Toggle \"Eavesdropper view\" to see exactly what Wireshark sees."),
            ["S_Capture"] = ("Ghi", "Capture"),
            ["S_Eavesdrop"] = ("Góc nhìn kẻ nghe lén", "Eavesdropper view"),
            ["S_Clear"] = ("Xóa", "Clear"),
            ["S_InspHint"] = ("Gửi một tin nhắn hoặc file cho peer để thấy bắt tay ECDHE, chữ ký ECDSA và các record AES-GCM.",
                              "Send a message or file to a peer to watch the ECDHE handshake, ECDSA signature and AES-GCM records."),

            ["S_LabIntro"] = ("Tự tấn công chính giao thức của app bằng proxy MITM trên 127.0.0.1 — 13 đòn kinh điển, mỗi đòn có bằng chứng đo được. Chạy cô lập, không ảnh hưởng phiên thật.",
                              "Attack the app's own protocol through a MITM proxy on 127.0.0.1 — 13 classic attacks, each with measured evidence. Fully isolated from real sessions."),
            ["S_RunLab"] = ("Chạy toàn bộ tấn công", "Run all attacks"),
            ["S_Defense"] = ("Phòng thủ", "Defense"),
            ["S_Evidence"] = ("Bằng chứng", "Evidence"),

            ["S_ToolsIntro"] = ("Chẩn đoán mạng: ICMP ping, traceroute (TTL tăng dần), DNS; đo đường truyền mã hóa tới peer (RTT, jitter, thông lượng).",
                                "Diagnostics: ICMP ping, traceroute (incrementing TTL), DNS; encrypted link test to a peer (RTT, jitter, throughput)."),
            ["S_Target"] = ("Đích (IP / tên miền)", "Target (IP / hostname)"),
            ["S_LinkTest"] = ("Đo đường truyền mã hóa tới peer", "Encrypted link test to peer"),
            ["S_Run"] = ("Chạy", "Run"),
            ["S_NoPeers"] = ("(chưa có phiên nào đang mở)", "(no active sessions)"),

            // ---- An ninh ----
            ["L_KeyChangedChat"] = ("⚠ CẢNH BÁO: tên máy \"{0}\" trước đây thuộc danh tính {1}, nay là {2}!",
                                    "⚠ WARNING: the name \"{0}\" used to belong to identity {1}, now it is {2}!"),
            ["L_KeyChangedTitle"] = ("Cảnh báo an ninh", "Security warning"),
            ["L_KeyChangedBody"] = ("Danh tính mật mã của \"{0}\" đã THAY ĐỔI!\n\nTrước: {1}{3}\nNay:   {2}\n\n" +
                                    "Có thể máy đó cài lại app... hoặc một máy KHÁC đang mạo danh.\n" +
                                    "Hãy so safety number với người bên kia trước khi gửi thông tin nhạy cảm.",
                                    "The cryptographic identity of \"{0}\" has CHANGED!\n\nWas: {1}{3}\nNow: {2}\n\n" +
                                    "That machine may have reinstalled the app... or a DIFFERENT machine is impersonating it.\n" +
                                    "Compare safety numbers with the other person before sending anything sensitive."),
            ["L_WasVerified"] = ("  (đã từng được XÁC MINH!)", "  (was VERIFIED!)"),
            ["L_NewIdentity"] = ("Lần đầu gặp danh tính này — hãy so safety number nếu cần chắc chắn",
                                 "First time seeing this identity — compare safety numbers to be sure"),
        };

        /// <summary>Gọi MỘT LẦN ở đầu MainWindow, trước InitializeComponent.</summary>
        public static void Initialize()
        {
            string code = VI;
            try
            {
                if (File.Exists(ConfigPath))
                {
                    string saved = File.ReadAllText(ConfigPath).Trim();
                    if (saved is VI or EN) code = saved;
                }
            }
            catch { /* cfg hỏng → mặc định VI */ }
            Apply(code, persist: false);
        }

        public static void Toggle() => Apply(Current == VI ? EN : VI);

        public static void Apply(string code, bool persist = true)
        {
            Current = code;
            foreach (var (key, (vi, en)) in Strings)
                Application.Current.Resources[key] = code == EN ? en : vi;

            if (!persist) return;
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
                File.WriteAllText(ConfigPath, code);
            }
            catch { /* không lưu được cũng không sao */ }
        }

        /// <summary>Chọn chuỗi động theo ngôn ngữ hiện tại (dùng cho nội dung sinh ra lúc chạy: kết quả quét, cảnh báo...).</summary>
        public static string Pick(string vi, string en) => Current == EN ? en : vi;

        /// <summary>Lấy chuỗi cho code-behind: string.Format(Localization.T("key"), args...)</summary>
        public static string T(string key)
            => Application.Current?.Resources[key] as string ?? key;
    }
}
