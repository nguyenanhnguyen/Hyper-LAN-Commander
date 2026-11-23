using System;
using System.IO;
using System.Linq;
using System.Threading;

namespace networkApp
{
    /// <summary>
    /// Hồ sơ chạy của một instance: thư mục dữ liệu (danh tính, danh bạ tin cậy),
    /// thư mục nhận file, cổng TCP mong muốn và tên hiển thị.
    ///
    /// Mở app LẦN THỨ HAI trên cùng máy → tự động dùng hồ sơ "2" với danh tính riêng
    /// (named mutex phát hiện instance đang chạy). Nhờ vậy demo/test trên 1 máy không cần
    /// cấu hình gì: hai cửa sổ tự thấy nhau qua discovery và chat/gửi file như hai máy thật.
    ///
    /// Biến môi trường (tùy chọn): HLC_PROFILE (ép tên hồ sơ), HLC_PORT (cổng TCP), HLC_NAME (tên hiển thị).
    /// </summary>
    public sealed class AppProfile : IDisposable
    {
        public string Name { get; }
        public string DataDir { get; }
        public string DownloadDir { get; }
        public int PreferredTcpPort { get; }
        public string DisplayName { get; }
        public bool IsDefault => Name == "default";

        private Mutex? _mutex;

        public static string RootDataDir { get; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "HyperLAN");

        private AppProfile(string name, Mutex? mutex)
        {
            Name = name;
            _mutex = mutex;

            string downloads = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "HyperLAN");
            DataDir = IsDefault ? RootDataDir : Path.Combine(RootDataDir, "profiles", name);
            DownloadDir = IsDefault ? downloads : Path.Combine(downloads, "profile-" + name);
            Directory.CreateDirectory(DataDir);
            Directory.CreateDirectory(DownloadDir);

            int port = int.TryParse(Environment.GetEnvironmentVariable("HLC_PORT"), out int p) && p is > 0 and < 65536
                ? p : MessagingService.DefaultPort;
            PreferredTcpPort = port;

            string? envName = Environment.GetEnvironmentVariable("HLC_NAME");
            DisplayName = !string.IsNullOrWhiteSpace(envName) ? envName.Trim()
                        : IsDefault ? Environment.MachineName
                        : $"{Environment.MachineName} #{name}";
        }

        public static AppProfile Acquire()
        {
            string? forced = Environment.GetEnvironmentVariable("HLC_PROFILE");
            if (!string.IsNullOrWhiteSpace(forced))
            {
                string n = Sanitize(forced);
                return new AppProfile(n, TryLock(n));
            }

            for (int i = 1; i <= 32; i++)
            {
                string name = i == 1 ? "default" : i.ToString();
                Mutex? m = TryLock(name);
                if (m is not null) return new AppProfile(name, m);
            }
            return new AppProfile("tmp-" + Environment.ProcessId, null);
        }

        private static Mutex? TryLock(string name)
        {
            var m = new Mutex(false, $@"Local\HyperLAN.Commander.{name}");
            try
            {
                if (m.WaitOne(0)) return m;
            }
            catch (AbandonedMutexException)
            {
                return m; // instance trước bị crash — mutex thuộc về ta
            }
            m.Dispose();
            return null;
        }

        private static string Sanitize(string s)
        {
            var chars = s.Trim().Where(c => char.IsLetterOrDigit(c) || c is '-' or '_').Take(32).ToArray();
            return chars.Length == 0 ? "custom" : new string(chars);
        }

        public void Dispose()
        {
            if (_mutex is null) return;
            try { _mutex.ReleaseMutex(); } catch { }
            _mutex.Dispose();
            _mutex = null;
        }
    }
}
