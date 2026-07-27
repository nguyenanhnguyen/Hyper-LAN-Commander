using System;
using System.Collections.Generic;
using System.IO;
using System.Windows;

namespace networkApp
{
    /// <summary>
    /// Song ngữ EN/VI theo cơ chế DynamicResource của WPF:
    /// - Mọi chuỗi UI nằm ở đây, bơm vào Application.Resources.
    /// - Label trong XAML dùng {DynamicResource key} → đổi ngôn ngữ là
    ///   TỰ CẬP NHẬT ngay, không cần restart.
    /// - Chuỗi động trong code lấy qua Localization.T(key) + string.Format.
    /// - Lựa chọn được lưu ở %AppData%\HyperLAN\lang.cfg cho lần mở sau.
    /// </summary>
    public static class Localization
    {
        public const string VI = "vi";
        public const string EN = "en";
        public static string Current { get; private set; } = VI;

        private static readonly string ConfigPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "HyperLAN", "lang.cfg");

        // key → (tiếng Việt, English)
        private static readonly Dictionary<string, (string vi, string en)> Strings = new()
        {
            // Nút chuyển ngôn ngữ hiển thị NGÔN NGỮ SẼ CHUYỂN SANG
            ["L_LangToggle"] = ("EN", "VI"),

            // ---- Nhãn tĩnh trong XAML ----
            ["L_YourIP"] = ("Địa chỉ IP của bạn:", "Your IP address:"),
            ["L_StatusReady"] = ("Trạng thái: Sẵn sàng", "Status: Ready"),
            ["L_Devices"] = ("Thiết bị trong mạng:", "Devices on this network:"),
            ["L_Scan"] = ("QUÉT MẠNG", "SCAN NETWORK"),
            ["L_Connect"] = ("Kết nối", "Connect"),
            ["L_ManualTooltip"] = ("Nhập IP:port để kết nối thủ công. Test trên 1 máy: gõ cổng của instance kia, vd 8890.",
                                  "Enter IP:port to connect manually. Single-machine test: type the other instance's port, e.g. 8890."),
            ["L_ManualName"] = ("(thủ công)", "(manual)"),
            ["L_ConnectFail"] = ("Kết nối thất bại: {0}", "Connection failed: {0}"),
            ["L_ChatEmpty"] = ("Chọn một thiết bị bên trái để bắt đầu chat",
                                  "Select a device on the left to start chatting"),
            ["L_Send"] = ("Gửi", "Send"),
            ["L_FileTooltip"] = ("Gửi file (bên kia sẽ được hỏi trước khi nhận)",
                                  "Send a file (the receiver is asked before accepting)"),
            ["L_FpTooltip"] = ("Danh tính mật mã của máy này — không thể giả mạo. Đọc cho bạn bè để họ đối chiếu.",
                                  "This machine's cryptographic identity — cannot be forged. Read it aloud so peers can verify."),

            // ---- Chuỗi động trong code ----
            ["L_Scanning"] = ("Trạng thái: Đang quét...", "Status: Scanning..."),
            ["L_ScanDone"] = ("Quét xong: {0} thiết bị", "Scan complete: {0} device(s)"),
            ["L_ScanNone"] = ("Quét xong: không thấy thiết bị nào", "Scan complete: no devices found"),
            ["L_ScanError"] = ("Lỗi quét: {0}", "Scan error: {0}"),
            ["L_Seen"] = ("Đã thấy: {0}", "Found: {0}"),
            ["L_TcpConnected"] = ("TCP: {0} đã kết nối", "TCP: {0} connected"),
            ["L_TcpDisconnected"] = ("TCP: {0} đã ngắt", "TCP: {0} disconnected"),
            ["L_Verified"] = ("Đã xác thực: {0} ({1})", "Verified: {0} ({1})"),
            ["L_ChatWith"] = ("Chat với {0}", "Chat with {0}"),
            ["L_ConnClosed"] = ("— Kết nối đã đóng —", "— Connection closed —"),
            ["L_SelectFirst"] = ("Hãy chọn một thiết bị trước", "Select a device first"),
            ["L_SendFail"] = ("— Gửi thất bại: {0} —", "— Send failed: {0} —"),
            ["L_You"] = ("Bạn", "You"),
            ["L_Unknown"] = ("(chưa rõ tên)", "(unknown)"),

            // ---- Truyền file ----
            ["L_OfferTitle"] = ("Yêu cầu gửi file", "File transfer request"),
            ["L_OfferBody"] = ("{0} muốn gửi file:\n\n{1}  ({2} MB){3}\n\nNhận file này?",
                                  "{0} wants to send you a file:\n\n{1}  ({2} MB){3}\n\nAccept this file?"),
            ["L_OfferResume"] = ("\n(Đã có {0}% từ lần trước — sẽ tải tiếp)",
                                  "\n({0}% already received — the transfer will resume)"),
            ["L_ProgSend"] = ("Gửi", "Sending"),
            ["L_ProgRecv"] = ("Nhận", "Receiving"),
            ["L_SentDone"] = ("— Đã gửi xong: {0} —", "— Sent: {0} —"),
            ["L_RecvDone"] = ("— Đã nhận file: {0} —", "— File received: {0} —"),
            ["L_SentStatus"] = ("Gửi file hoàn tất", "File sent successfully"),
            ["L_RecvStatus"] = ("Nhận file hoàn tất", "File received successfully"),
            ["L_FileFail"] = ("File {0}: {1}", "File {0}: {1}"),
            ["L_Inviting"] = ("— Đang mời {0} nhận file {1}... —", "— Inviting {0} to receive {1}... —"),
            ["L_ChooseFile"] = ("Chọn file để gửi", "Choose a file to send"),
            ["L_Canceled"] = ("— Đã hủy truyền file: {0} (phần dở dang được giữ để tải tiếp) —",
                                  "— Transfer canceled: {0} (partial data kept for resume) —"),
            ["L_CancelTooltip"] = ("Hủy truyền file — phần đã nhận vẫn giữ để tải tiếp sau",
                                  "Cancel the transfer — received data is kept so it can resume later"),

            // ---- An ninh ----
            ["L_KeyChangedChat"] = ("⚠ CẢNH BÁO: danh tính tại {0} đã THAY ĐỔI ({1} → {2})!",
                                     "⚠ WARNING: the identity at {0} has CHANGED ({1} → {2})!"),
            ["L_KeyChangedTitle"] = ("Cảnh báo an ninh", "Security warning"),
            ["L_KeyChangedBody"] = ("Danh tính mật mã tại {0} đã THAY ĐỔI!\n\nTrước: {1}\nNay:   {2}\n\n" +
                                     "Có thể máy đó cài lại app... hoặc một máy KHÁC đang chiếm IP này.\n" +
                                     "Hãy xác nhận với người bên kia (đọc ID cho nhau) trước khi gửi thông tin nhạy cảm.",
                                     "The cryptographic identity at {0} has CHANGED!\n\nWas: {1}\nNow: {2}\n\n" +
                                     "That machine may have reinstalled the app... or a DIFFERENT machine is using this IP.\n" +
                                     "Verify with the other person (compare IDs out loud) before sending anything sensitive."),
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
            Apply(code);
        }

        public static void Toggle() => Apply(Current == VI ? EN : VI);

        public static void Apply(string code)
        {
            Current = code;
            foreach (var (key, (vi, en)) in Strings)
                Application.Current.Resources[key] = code == EN ? en : vi;

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(ConfigPath)!);
                File.WriteAllText(ConfigPath, code);
            }
            catch { /* không lưu được cũng không sao */ }
        }

        /// <summary>Lấy chuỗi cho code-behind: string.Format(Localization.T("key"), args...)</summary>
        public static string T(string key)
            => Application.Current.Resources[key] as string ?? key;
    }
}