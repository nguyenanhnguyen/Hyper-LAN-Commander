using System;
using System.Collections.Generic;
using System.Linq;

namespace networkApp.Security
{
    public enum SecurityCategory { Protocol, Arp, Network, Lan, Device, Identity }

    /// <summary>Một sự kiện an ninh (giống một dòng trong SIEM).</summary>
    public sealed record SecurityEvent(DateTime Time, Severity Severity, SecurityCategory Category, string Title, string Detail)
    {
        public string TimeText => Time.ToString("HH:mm:ss");
        public string SeverityText => Knowledge.SeverityLabel(Severity);
    }

    /// <summary>
    /// Nhật ký sự kiện an ninh tập trung: phát hiện ARP spoofing, gói bị sửa, chữ ký sai,
    /// danh tính đổi, cổng nguy hiểm... Thread-safe; UI nghe sự kiện Added.
    /// </summary>
    public sealed class SecurityLog
    {
        private readonly List<SecurityEvent> _events = new();
        private readonly Dictionary<string, DateTime> _dedupe = new();
        private readonly object _lock = new();

        public event Action<SecurityEvent>? Added;

        /// <summary>
        /// Ghi sự kiện. Cùng <paramref name="dedupeKey"/> trong <paramref name="dedupeWindow"/> (mặc định 10 phút)
        /// chỉ ghi một lần — tình trạng kéo dài không làm ngập nhật ký.
        /// </summary>
        public void Add(Severity sev, SecurityCategory cat, string title, string detail, string? dedupeKey = null,
                        TimeSpan? dedupeWindow = null)
        {
            var ev = new SecurityEvent(DateTime.Now, sev, cat, title, detail);
            lock (_lock)
            {
                if (dedupeKey is not null)
                {
                    if (_dedupe.TryGetValue(dedupeKey, out var last) && DateTime.Now - last < (dedupeWindow ?? TimeSpan.FromMinutes(10)))
                        return;
                    _dedupe[dedupeKey] = DateTime.Now;
                }
                _events.Add(ev);
                if (_events.Count > 5000) _events.RemoveRange(0, 1000);
            }
            try { Added?.Invoke(ev); } catch { }
        }

        public IReadOnlyList<SecurityEvent> Snapshot()
        {
            lock (_lock) return _events.ToList();
        }
    }
}
