using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace networkApp
{
    /// <summary>
    /// Danh bạ tin cậy TOFU (Trust On First Use) — lưu bền tại known_peers.json.
    ///
    /// Mô hình giống SSH known_hosts / Signal:
    /// - Lần đầu gặp một danh tính → ghi nhớ (đánh dấu "MỚI" trên UI).
    /// - Một TÊN MÁY quen nay xuất hiện với fingerprint KHÁC → cảnh báo
    ///   (máy cài lại app... hoặc kẻ khác đang mạo danh).
    /// - Người dùng đối chiếu safety number → đánh dấu "Đã xác minh".
    ///
    /// Không khóa theo IP: IP đổi do DHCP là chuyện thường, cảnh báo theo IP chỉ gây
    /// báo động giả — đúng tinh thần "danh tính ≠ địa chỉ".
    /// </summary>
    public sealed class TrustStore
    {
        public sealed class KnownPeer
        {
            public string Fingerprint { get; set; } = "";
            public string Name { get; set; } = "";
            public byte[]? PublicKey { get; set; }
            public DateTime FirstSeen { get; set; }
            public DateTime LastSeen { get; set; }
            public string? LastAddress { get; set; }
            public int LastPort { get; set; }
            public bool Verified { get; set; }
            public bool Superseded { get; set; }
        }

        public sealed record Observation(bool IsNew, KnownPeer Peer, KnownPeer? Conflict);

        private readonly string _path;
        private readonly object _lock = new();
        private readonly Dictionary<string, KnownPeer> _peers;

        public TrustStore(string dataDir)
        {
            _path = Path.Combine(dataDir, "known_peers.json");
            _peers = Load(_path);
        }

        private static Dictionary<string, KnownPeer> Load(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    var list = JsonSerializer.Deserialize<List<KnownPeer>>(File.ReadAllText(path));
                    if (list is not null)
                        return list.Where(p => !string.IsNullOrEmpty(p.Fingerprint))
                                   .GroupBy(p => p.Fingerprint)
                                   .ToDictionary(g => g.Key, g => g.First());
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Trust] load failed: {ex.Message}");
            }
            return new Dictionary<string, KnownPeer>();
        }

        private void SaveLocked()
        {
            try
            {
                AtomicFile.WriteAllText(_path, JsonSerializer.Serialize(_peers.Values.ToList(),
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Trust] save failed: {ex.Message}");
            }
        }

        /// <summary>Ghi nhận một phiên đã XÁC THỰC (chữ ký hợp lệ) với danh tính này.</summary>
        public Observation Observe(string fingerprint, string name, byte[] publicKey, string? address, int port)
        {
            lock (_lock)
            {
                bool isNew = !_peers.TryGetValue(fingerprint, out KnownPeer? peer);
                KnownPeer? conflict = null;

                if (isNew)
                {
                    conflict = _peers.Values.FirstOrDefault(p =>
                        !p.Superseded && p.Fingerprint != fingerprint &&
                        string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
                    if (conflict is not null) conflict.Superseded = true;

                    peer = new KnownPeer { Fingerprint = fingerprint, FirstSeen = DateTime.Now };
                    _peers[fingerprint] = peer;
                }

                peer!.Name = name;
                peer.PublicKey = publicKey;
                peer.LastSeen = DateTime.Now;
                peer.LastAddress = address;
                peer.LastPort = port;
                peer.Superseded = false;
                SaveLocked();
                return new Observation(isNew, peer, conflict);
            }
        }

        public void SetVerified(string fingerprint, bool verified)
        {
            lock (_lock)
            {
                if (_peers.TryGetValue(fingerprint, out var p))
                {
                    p.Verified = verified;
                    SaveLocked();
                }
            }
        }

        public KnownPeer? Get(string fingerprint)
        {
            lock (_lock) return _peers.TryGetValue(fingerprint, out var p) ? p : null;
        }

        public IReadOnlyList<KnownPeer> Recent(TimeSpan maxAge)
        {
            lock (_lock)
                return _peers.Values.Where(p => !p.Superseded && DateTime.Now - p.LastSeen <= maxAge).ToList();
        }
    }
}
