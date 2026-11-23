using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Threading;

namespace networkApp
{
    public partial class App : Application
    {
        private static readonly string CrashLog = Path.Combine(AppProfile.RootDataDir, "error.log");

        protected override void OnStartup(StartupEventArgs e)
        {
            // Lưới an toàn: một lỗi bất ngờ ở UI không được làm sập app (và mất transfer đang chạy)
            DispatcherUnhandledException += OnDispatcherUnhandledException;
            TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                Log(args.Exception);
                args.SetObserved();
            };
            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                if (args.ExceptionObject is Exception ex) Log(ex);
            };
            base.OnStartup(e);
        }

        private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            Log(e.Exception);
            e.Handled = true;
            // Lỗi khi dựng cửa sổ chính (vd. không mở được cổng mạng) → báo rồi thoát hẳn
            bool fatal = MainWindow is null || !MainWindow.IsLoaded;
            MessageBox.Show(e.Exception.Message, Localization.T("L_Fatal"), MessageBoxButton.OK,
                fatal ? MessageBoxImage.Error : MessageBoxImage.Warning);
            if (fatal) Shutdown(1);
        }

        internal static void Log(Exception ex)
        {
            try
            {
                Directory.CreateDirectory(AppProfile.RootDataDir);
                File.AppendAllText(CrashLog, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}\n\n");
            }
            catch { }
        }
    }
}
