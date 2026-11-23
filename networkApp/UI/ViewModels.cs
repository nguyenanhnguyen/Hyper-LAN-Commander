using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;

namespace networkApp
{
    public abstract class ObservableObject : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
        {
            if (Equals(field, value)) return false;
            field = value;
            OnPropertyChanged(name);
            return true;
        }

        protected void OnPropertyChanged([CallerMemberName] string? name = null)
            => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

        protected void OnAllChanged() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    internal static class Fmt
    {
        public static string Bytes(double b)
        {
            string[] u = { "B", "KB", "MB", "GB", "TB" };
            int i = 0;
            while (b >= 1024 && i < u.Length - 1) { b /= 1024; i++; }
            return i == 0 ? $"{b:0} {u[i]}" : $"{b:0.0} {u[i]}";
        }

        public static string Duration(double seconds)
        {
            if (double.IsNaN(seconds) || double.IsInfinity(seconds) || seconds < 0) return "--:--";
            var t = TimeSpan.FromSeconds(Math.Ceiling(seconds));
            return t.TotalHours >= 1 ? t.ToString(@"h\:mm\:ss") : t.ToString(@"mm\:ss");
        }

        public static string F(string key, params object[] args) => string.Format(Localization.T(key), args);
    }

    // ======================================================================
    //  PEER
    // ======================================================================

    public sealed class PeerViewModel : ObservableObject
    {
        public PeerViewModel(string fingerprint, string name)
        {
            Fingerprint = fingerprint;
            _name = name;
        }

        public string Fingerprint { get; }
        public string ShortFingerprint => Fingerprint.Length > 9 ? Fingerprint[..9] : Fingerprint;

        private string _name;
        public string Name
        {
            get => _name;
            set { if (Set(ref _name, value)) { OnPropertyChanged(nameof(Initials)); OnPropertyChanged(nameof(SortKey)); } }
        }

        public string Initials
        {
            get
            {
                var parts = Name.Split(new[] { ' ', '-', '_', '.', '#' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 0) return "?";
                string s = parts.Length == 1 ? parts[0][..Math.Min(2, parts[0].Length)] : $"{parts[0][0]}{parts[1][0]}";
                return s.ToUpperInvariant();
            }
        }

        private string _endpoint = "";
        public string Endpoint { get => _endpoint; set => Set(ref _endpoint, value); }

        private bool _isDiscovered;
        public bool IsDiscovered
        {
            get => _isDiscovered;
            set { if (Set(ref _isDiscovered, value)) OnStatusChanged(); }
        }

        private bool _isConnected;
        public bool IsConnected
        {
            get => _isConnected;
            set { if (Set(ref _isConnected, value)) { if (!value) RttMs = -1; OnStatusChanged(); } }
        }

        public bool IsOnline => IsConnected || IsDiscovered;

        /// <summary>0 = đang có phiên mã hóa, 1 = thấy trên mạng, 2 = offline.</summary>
        public int Status => IsConnected ? 0 : IsDiscovered ? 1 : 2;

        public string StatusText => Localization.T(IsConnected ? "L_StSecure" : IsDiscovered ? "L_StOnline" : "L_StOffline");

        private void OnStatusChanged()
        {
            OnPropertyChanged(nameof(IsOnline));
            OnPropertyChanged(nameof(Status));
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(SortKey));
        }

        public string SortKey => $"{Status}{Name.ToLowerInvariant()}";

        private int _rttMs = -1;
        public int RttMs
        {
            get => _rttMs;
            set { if (Set(ref _rttMs, value)) { OnPropertyChanged(nameof(RttText)); OnPropertyChanged(nameof(HasRtt)); } }
        }
        public bool HasRtt => RttMs >= 0;
        public string RttText => RttMs < 0 ? "" : RttMs < 1 ? "<1 ms" : $"{RttMs} ms";

        private bool _isVerified;
        public bool IsVerified { get => _isVerified; set => Set(ref _isVerified, value); }

        private bool _isNew;
        public bool IsNew { get => _isNew; set => Set(ref _isNew, value); }

        private int _unread;
        public int Unread
        {
            get => _unread;
            set { if (Set(ref _unread, value)) OnPropertyChanged(nameof(HasUnread)); }
        }
        public bool HasUnread => Unread > 0;

        public byte[]? PublicKey { get; set; }
        public string? SessionId { get; set; }
        public DateTime? LastSeen { get; set; }

        public void RefreshTexts() => OnPropertyChanged(nameof(StatusText));
    }

    // ======================================================================
    //  CHAT
    // ======================================================================

    public enum ChatKind { Mine, Theirs, System, Warning, Transfer }

    public sealed class ChatItem : ObservableObject
    {
        public ChatKind Kind { get; init; }
        public string Text { get; init; } = "";
        public string Time { get; init; } = DateTime.Now.ToString("HH:mm");
        public TransferViewModel? Transfer { get; init; }

        private string _status = "";
        /// <summary>Tin của mình: ⏳ đang gửi · ✓ đã ghi xuống kênh mã hóa · ✗ lỗi.</summary>
        public string Status { get => _status; set => Set(ref _status, value); }
    }

    public sealed class ChatTemplateSelector : DataTemplateSelector
    {
        public DataTemplate? Mine { get; set; }
        public DataTemplate? Theirs { get; set; }
        public DataTemplate? System { get; set; }
        public DataTemplate? Warning { get; set; }
        public DataTemplate? Transfer { get; set; }

        public override DataTemplate? SelectTemplate(object item, DependencyObject container)
            => (item as ChatItem)?.Kind switch
            {
                ChatKind.Mine => Mine,
                ChatKind.Theirs => Theirs,
                ChatKind.Warning => Warning,
                ChatKind.Transfer => Transfer,
                _ => System,
            };
    }

    // ======================================================================
    //  TRANSFER
    // ======================================================================

    public sealed class TransferViewModel : ObservableObject
    {
        private TransferSnapshot _s;

        public TransferViewModel(TransferSnapshot s, string peerName)
        {
            _s = s;
            PeerName = peerName;
        }

        public Guid Id => _s.Id;
        public string PeerName { get; set; }
        public TransferDirection Direction => _s.Direction;
        public TransferState State => _s.State;
        public bool IsSend => _s.Direction == TransferDirection.Send;
        public string FileName => _s.FileName;
        public string? LocalPath => _s.LocalPath;
        public HorizontalAlignment Alignment => IsSend ? HorizontalAlignment.Right : HorizontalAlignment.Left;
        public string Icon => IsSend ? "⬆" : "⬇";

        public double Percent => _s.Size <= 0 ? (_s.State == TransferState.Completed ? 100 : 0) : _s.Done * 100.0 / _s.Size;

        public bool IsIndeterminate => _s.State is TransferState.Preparing or TransferState.Reconnecting
                                                  or TransferState.Verifying or TransferState.Offering;

        public bool ShowProgress => _s.State is TransferState.Transferring or TransferState.Preparing
            or TransferState.Reconnecting or TransferState.Paused or TransferState.Verifying or TransferState.Offering;

        public bool CanDecide => _s.State == TransferState.AwaitingDecision;
        public bool CanCancel => _s.State is TransferState.Offering or TransferState.Transferring or TransferState.Preparing
                                            or TransferState.Reconnecting or TransferState.Paused;
        public bool CanOpen => _s.State == TransferState.Completed && !IsSend && _s.LocalPath is not null;

        /// <summary>0 = đang chạy, 1 = xong, 2 = lỗi/hủy, 3 = chờ — để XAML tô màu.</summary>
        public int Tone => _s.State switch
        {
            TransferState.Completed => 1,
            TransferState.Failed or TransferState.Rejected or TransferState.Canceled => 2,
            TransferState.AwaitingDecision or TransferState.Paused or TransferState.Reconnecting => 3,
            _ => 0,
        };

        public string MetaText => $"{Fmt.Bytes(_s.Size)} · " + Fmt.F(IsSend ? "L_TrTo" : "L_TrFrom", PeerName);

        public string StatusText
        {
            get
            {
                string resume = _s.ResumedFrom > 0 && _s.Size > 0
                    ? Fmt.F("L_TrResumedFrom", (int)(_s.ResumedFrom * 100 / _s.Size)) : "";
                return _s.State switch
                {
                    TransferState.Offering => Fmt.F("L_TrOffering", PeerName),
                    TransferState.AwaitingDecision => Localization.T("L_TrAsk") +
                        (_s.ResumedFrom > 0 && _s.Size > 0 ? Fmt.F("L_OfferResume", (int)(_s.ResumedFrom * 100 / _s.Size)) : ""),
                    TransferState.Preparing => Localization.T("L_TrPreparing"),
                    TransferState.Transferring => Localization.T(IsSend ? "L_ProgSend" : "L_ProgRecv") + resume,
                    TransferState.Reconnecting => Fmt.F("L_TrReconnecting", _s.Reconnects),
                    TransferState.Paused => Localization.T("L_TrPaused"),
                    TransferState.Verifying => Localization.T("L_TrVerifying"),
                    TransferState.Completed => Localization.T(IsSend ? "L_TrDelivered" : "L_TrReceived") + resume,
                    TransferState.Rejected => Localization.T("L_TrRejected"),
                    TransferState.Canceled => Localization.T(_s.Detail == "peer" ? "L_TrCanceledPeer" : "L_TrCanceled"),
                    TransferState.Failed => ErrorText(),
                    _ => "",
                };
            }
        }

        private string ErrorText() => _s.Error switch
        {
            TransferError.Timeout => Localization.T("L_ErrTimeout"),
            TransferError.Integrity => Localization.T("L_ErrIntegrity"),
            TransferError.DiskFull => Localization.T("L_ErrDiskFull"),
            TransferError.PeerGone => Localization.T("L_ErrPeerGone"),
            TransferError.Busy => Localization.T("L_ErrBusy"),
            TransferError.Rejected => Localization.T("L_TrRejected"),
            _ => Fmt.F("L_ErrIo", _s.Detail ?? "?"),
        };

        public string MetricsText
        {
            get
            {
                switch (_s.State)
                {
                    case TransferState.Transferring:
                    {
                        string eta = _s.BytesPerSecond > 1 ? Fmt.Duration((_s.Size - _s.Done) / _s.BytesPerSecond) : "--:--";
                        return $"{Fmt.Bytes(_s.Done)} / {Fmt.Bytes(_s.Size)}  ·  {Fmt.Bytes(_s.BytesPerSecond)}/s  ·  " +
                               Fmt.F("L_TrEta", eta);
                    }
                    case TransferState.Paused:
                    case TransferState.Reconnecting:
                    case TransferState.Preparing:
                    case TransferState.Verifying:
                        return $"{Fmt.Bytes(_s.Done)} / {Fmt.Bytes(_s.Size)}  ({Percent:0}%)";
                    case TransferState.Completed:
                        return _s.Detail is { Length: >= 16 } h ? $"SHA-256  {h[..16].ToLowerInvariant()}…" : "";
                    default:
                        return "";
                }
            }
        }

        public void Apply(TransferSnapshot s)
        {
            _s = s;
            OnAllChanged();
        }

        public void RefreshTexts() => OnAllChanged();
    }
}
