using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using networkApp.Security;

namespace networkApp
{
    // ======================================================================
    //  CONVERTERS
    // ======================================================================

    public sealed class SeverityBrushConverter : IValueConverter
    {
        private static readonly Brush[] Brushes =
        {
            Frozen("#64748B"), Frozen("#0EA5E9"), Frozen("#F59E0B"), Frozen("#EF4444"), Frozen("#991B1B"),
        };

        internal static Brush Frozen(string hex)
        {
            var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return b;
        }

        public static Brush For(Severity s) => Brushes[Math.Clamp((int)s, 0, 4)];

        public object Convert(object value, Type t, object p, CultureInfo c)
            => value is Severity s ? For(s) : Brushes[0];

        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotSupportedException();
    }

    public sealed class SeverityTextConverter : IValueConverter
    {
        public object Convert(object value, Type t, object p, CultureInfo c)
            => value is Severity s ? Knowledge.SeverityLabel(s) : "";

        public object ConvertBack(object v, Type t, object p, CultureInfo c) => throw new NotSupportedException();
    }

    // ======================================================================
    //  LAN AUDIT
    // ======================================================================

    public sealed class ServiceRowVm
    {
        public required int Port { get; init; }
        public required string Service { get; init; }
        public required Severity Risk { get; init; }
        public required string Banner { get; init; }
        public required string Why { get; init; }
        public required string Issues { get; init; }
        public bool HasIssues => Issues.Length > 0;
        public bool HasBanner => Banner.Length > 0;
        public string PortText => $"{Port}/tcp";
    }

    public sealed class HostRowVm : ObservableObject
    {
        public HostRowVm(HostResult h) => Update(h);

        public string Ip { get; private set; } = "";
        public uint SortKey { get; private set; }
        public string Mac { get; private set; } = "";
        public string Vendor { get; private set; } = "";
        public string HostName { get; private set; } = "";
        public string Tags { get; private set; } = "";
        public Severity Risk { get; private set; }
        public bool Scanning { get; private set; }
        public string Summary { get; private set; } = "";
        public List<ServiceRowVm> Services { get; private set; } = new();

        public void Update(HostResult h)
        {
            Ip = h.Ip.ToString();
            SortKey = Knowledge.ToUInt(h.Ip);
            Mac = h.Mac;
            Vendor = h.Vendor;
            HostName = h.HostName ?? "";
            var tags = new List<string>();
            if (h.IsSelf) tags.Add(Localization.Pick("MÁY NÀY", "THIS PC"));
            if (h.IsGateway) tags.Add("GATEWAY");
            if (h.PingMs >= 0) tags.Add($"ping {h.PingMs} ms");
            else tags.Add(Localization.Pick("chặn ping", "ping blocked"));
            Tags = string.Join("  ·  ", tags);
            List<ServiceFinding> svc;
            lock (h.Services) svc = h.Services.ToList();
            Services = svc.Select(s =>
            {
                var info = Knowledge.Describe(s.Port);
                return new ServiceRowVm
                {
                    Port = s.Port, Service = s.Service, Risk = s.Risk, Banner = s.Banner,
                    Why = Localization.Pick(info.WhyVi, info.WhyEn),
                    Issues = string.Join("\n", s.Issues.Select(i => "⚠ " + i)),
                };
            }).ToList();
            Risk = h.MaxRisk;
            Scanning = !h.PortsScanned;
            Summary = Scanning ? Localization.Pick("đang quét cổng…", "scanning ports…")
                    : svc.Count == 0 ? Localization.Pick("không có cổng nào trong danh mục đang mở", "no catalogued ports open")
                    : Localization.Pick($"{svc.Count} dịch vụ mở", $"{svc.Count} open service(s)");
            OnAllChanged();
        }
    }

    // ======================================================================
    //  PROTOCOL INSPECTOR
    // ======================================================================

    public sealed class TraceRowVm
    {
        public TraceRowVm(FrameTrace t)
        {
            Time = t.Time.ToString("HH:mm:ss.fff");
            Direction = t.Kind is "KEY" or "AUTH" or "CLOSE" ? "•" : t.Outgoing ? "→" : "←";
            Peer = t.Peer;
            Kind = t.Kind;
            Inner = t.Inner?.ToString() ?? (t.Kind == "Hello" ? "Hello" : t.Kind);
            Seq = t.Sequence is { } s ? s.ToString() : "";
            Bytes = t.WireBytes > 0 ? (t.Aggregated > 1 ? $"{t.WireBytes / 1024:N0} KB" : $"{t.WireBytes:N0} B") : "";
            Hex = t.CipherHex.Length > 0
                ? string.Join(" ", Enumerable.Range(0, t.CipherHex.Length / 2).Select(i => t.CipherHex.Substring(i * 2, 2))) + " …"
                : "";
            Note = t.Note;
            IsSealed = t.Kind == "Sealed";
            IsLocalEvent = t.Kind is "KEY" or "AUTH" or "CLOSE";
            Accent = t.Kind switch
            {
                "Hello" => SeverityBrushConverter.Frozen("#F59E0B"),
                "KEY" or "AUTH" => SeverityBrushConverter.Frozen("#22C55E"),
                "CLOSE" => SeverityBrushConverter.Frozen("#EF4444"),
                _ => SeverityBrushConverter.Frozen("#38BDF8"),
            };
        }

        public string Time { get; }
        public string Direction { get; }
        public string Peer { get; }
        public string Kind { get; }
        public string Inner { get; }
        public string Seq { get; }
        public string Bytes { get; }
        public string Hex { get; }
        public string Note { get; }
        public bool IsSealed { get; }
        public bool IsLocalEvent { get; }
        public Brush Accent { get; }
    }

    // ======================================================================
    //  ATTACK LAB
    // ======================================================================

    public sealed class LabRowVm
    {
        public LabRowVm(LabResult r)
        {
            Result = r;
            Blocked = r.Outcome == LabOutcome.Blocked;
            OutcomeText = r.Outcome switch
            {
                LabOutcome.Blocked => Localization.Pick("✓ ĐÃ CHẶN", "✓ BLOCKED"),
                LabOutcome.Vulnerable => Localization.Pick("✗ LỖ HỔNG", "✗ VULNERABLE"),
                _ => Localization.Pick("LỖI", "ERROR"),
            };
            OutcomeBrush = SeverityBrushConverter.Frozen(Blocked ? "#16A34A" : "#DC2626");
        }

        public LabResult Result { get; }
        public bool Blocked { get; }
        public string OutcomeText { get; }
        public Brush OutcomeBrush { get; }
        public string Attack => Result.Attack;
        public string Technique => Result.Technique;
        public string Defense => Result.Defense;
        public string Evidence => Result.Evidence;
        public string Elapsed => Result.ElapsedMs >= 1000 ? $"{Result.ElapsedMs / 1000.0:0.0} s" : $"{Result.ElapsedMs} ms";
    }

    public sealed class FindingRowVm
    {
        public required Severity Severity { get; init; }
        public required string Title { get; init; }
        public required string Detail { get; init; }
    }

    public sealed class PeerOption
    {
        public required string Fingerprint { get; init; }
        public required string Name { get; init; }
        public override string ToString() => $"{Name}  ({Fingerprint[..9]})";
    }
}
