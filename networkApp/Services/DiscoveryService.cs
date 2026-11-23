using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>Một peer được phát hiện trong LAN (thông tin TỰ KHAI — chưa xác thực).</summary>
    public sealed record DiscoveredPeer(Guid Instance, string Fingerprint, string Name, IPEndPoint TcpEndPoint)
    {
        public DateTime LastSeenUtc { get; set; } = DateTime.UtcNow;
    }

    /// <summary>Một card mạng IPv4 đang hoạt động.</summary>
    public sealed record LocalInterface(string Name, NetworkInterfaceType Type, IPAddress Address,
                                        IPAddress Mask, IPAddress? Broadcast, bool HasGateway, int Index)
    {
        public int PrefixLength => Mask.GetAddressBytes().Sum(b => System.Numerics.BitOperations.PopCount(b));
        public override string ToString() => $"{Address}/{PrefixLength}  ({Name})";
    }

    /// <summary>
    /// Zero-configuration discovery + presence (lấy cảm hứng từ mDNS/DNS-SD và SSDP):
    ///
    ///   Announce  — định kỳ ~5s, mọi máy đều biết ai đang online mà KHÔNG cần bấm quét
    ///   Query     — "ai ở đây?" (nút Quét mạng) → các máy trả Reply UNICAST về đúng người hỏi
    ///   Reply     — cũng được gửi khi lần đầu nghe Announce của máy mới → hai bên thấy nhau tức thì
    ///   Bye       — khi thoát app → biến mất khỏi danh sách ngay, không phải chờ hết hạn (~18s)
    ///
    /// GỬI ĐI ĐÂU: Windows chỉ đẩy 255.255.255.255 ra MỘT card mạng (card có metric tốt nhất),
    /// nên máy có Hyper-V / VPN / VirtualBox / Wi-Fi + Ethernet thường "không thấy nhau".
    /// Ở đây mỗi gói được phát tới:
    ///   • directed broadcast của TỪNG card (vd 192.168.1.255, 169.254.255.255 khi cắm cáp trực tiếp)
    ///   • multicast 239.255.72.67 trên TỪNG card (một số AP chặn broadcast nhưng cho multicast)
    ///   • 255.255.255.255 (dự phòng) và 127.0.0.1 (nhiều instance trên cùng máy, kể cả khi không có mạng)
    ///
    /// Gói tin: "HLC2" + 1 byte loại + JSON {I: instance, F: fingerprint, N: tên, P: cổng TCP}.
    /// Thông tin này CHƯA được tin: danh tính chỉ được công nhận sau khi bắt tay TCP ký số thành công.
    /// </summary>
    public sealed class DiscoveryService : IDisposable
    {
        public const int Port = 8888;
        private static readonly IPAddress MulticastGroup = IPAddress.Parse("239.255.72.67");
        private static readonly byte[] Magic = "HLC2"u8.ToArray();
        private const byte TAnnounce = 1, TQuery = 2, TReply = 3, TBye = 4;

        private static readonly TimeSpan AnnounceInterval = TimeSpan.FromSeconds(5);
        private static readonly TimeSpan PeerTtl = TimeSpan.FromSeconds(18);
        private const int SIO_UDP_CONNRESET = -1744830452;

        private sealed record Msg(Guid I, string F, string N, int P, int V);

        private readonly Guid _instance;
        private readonly string _fingerprint;
        private readonly string _name;
        private readonly int _tcpPort;
        private readonly CancellationTokenSource _cts = new();
        private readonly ConcurrentDictionary<string, DiscoveredPeer> _peers = new();   // theo fingerprint
        private readonly ConcurrentDictionary<Guid, long> _lastReplyTick = new();
        private readonly object _sendLock = new();

        private Socket? _shared;   // bind :8888 (ReuseAddress) — nhận broadcast/multicast
        private Socket? _unicast;  // bind cổng tạm — gửi đi + nhận Reply unicast (mỗi instance một cổng riêng)
        private volatile IReadOnlyList<LocalInterface> _interfaces = Array.Empty<LocalInterface>();
        private int _netChangePending;

        public event Action<DiscoveredPeer>? PeerSeen;   // mới thấy hoặc đổi địa chỉ/tên
        public event Action<DiscoveredPeer>? PeerLost;   // Bye hoặc hết hạn
        public event Action? NetworkChanged;

        public IReadOnlyList<LocalInterface> Interfaces => _interfaces;
        public bool ListeningOnSharedPort => _shared is not null;

        /// <summary>IP "chính": card có default gateway, ưu tiên Ethernet/Wi-Fi thật.</summary>
        public LocalInterface? Primary => _interfaces.FirstOrDefault();

        public DiscoveryService(Guid instance, string fingerprint, string name, int tcpPort)
        {
            _instance = instance;
            _fingerprint = fingerprint;
            _name = name;
            _tcpPort = tcpPort;
        }

        public void Start()
        {
            _interfaces = EnumerateInterfaces();

            // Socket chung :8888 — ReuseAddress để nhiều instance trên một máy cùng nghe được
            try
            {
                var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                s.EnableBroadcast = true;
                DisableConnReset(s);
                s.Bind(new IPEndPoint(IPAddress.Any, Port));
                _shared = s;
                JoinMulticast();
            }
            catch (SocketException ex)
            {
                System.Diagnostics.Debug.WriteLine($"[Discovery] cannot bind {Port}: {ex.Message}");
                _shared = null; // vẫn chạy được: gửi đi + nhận Reply qua socket unicast
            }

            var u = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            u.EnableBroadcast = true;
            u.MulticastLoopback = true;
            u.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1); // không ra khỏi LAN
            DisableConnReset(u);
            u.Bind(new IPEndPoint(IPAddress.Any, 0));
            _unicast = u;

            if (_shared is not null) _ = Task.Run(() => ReceiveLoopAsync(_shared));
            _ = Task.Run(() => ReceiveLoopAsync(_unicast));
            _ = Task.Run(PresenceLoopAsync);

            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
        }

        /// <summary>
        /// Windows: gửi UDP tới cổng đóng → ICMP "port unreachable" → lần ReceiveFrom KẾ TIẾP
        /// ném ConnectionReset. Tắt hành vi đó để một máy vừa thoát không làm "nấc" vòng nhận.
        /// </summary>
        private static void DisableConnReset(Socket s)
        {
            try { s.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null); } catch { }
        }

        private void JoinMulticast()
        {
            if (_shared is null) return;
            foreach (var iface in _interfaces)
            {
                try
                {
                    _shared.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.AddMembership,
                        new MulticastOption(MulticastGroup, iface.Address));
                }
                catch (SocketException) { /* đã là thành viên / card không hỗ trợ multicast */ }
            }
        }

        // ==================== GỬI ====================

        /// <summary>Quét chủ động: gửi Query 3 lần (UDP không đảm bảo tới nơi).</summary>
        public async Task ScanAsync()
        {
            for (int i = 0; i < 3 && !_cts.IsCancellationRequested; i++)
            {
                Broadcast(TQuery);
                await Task.Delay(300, _cts.Token).ConfigureAwait(false);
            }
        }

        private byte[] BuildPacket(byte type)
        {
            byte[] json = JsonSerializer.SerializeToUtf8Bytes(new Msg(_instance, _fingerprint, _name, _tcpPort, 2));
            byte[] pkt = new byte[Magic.Length + 1 + json.Length];
            Magic.CopyTo(pkt, 0);
            pkt[Magic.Length] = type;
            json.CopyTo(pkt, Magic.Length + 1);
            return pkt;
        }

        private void Broadcast(byte type)
        {
            if (_unicast is null) return;
            byte[] pkt = BuildPacket(type);
            var groupEp = new IPEndPoint(MulticastGroup, Port);

            lock (_sendLock)
            {
                var sentBroadcast = new HashSet<IPAddress>();
                foreach (var iface in _interfaces)
                {
                    if (iface.Broadcast is not null && sentBroadcast.Add(iface.Broadcast))
                        TrySend(pkt, new IPEndPoint(iface.Broadcast, Port));
                    try
                    {
                        _unicast.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
                            iface.Address.GetAddressBytes());
                        TrySend(pkt, groupEp);
                    }
                    catch (SocketException) { }
                }
                TrySend(pkt, new IPEndPoint(IPAddress.Broadcast, Port));
                TrySend(pkt, new IPEndPoint(IPAddress.Loopback, Port));
            }
        }

        private void TrySend(byte[] pkt, IPEndPoint ep)
        {
            try { _unicast!.SendTo(pkt, ep); }
            catch (SocketException) { /* card vừa rớt / mạng chặn broadcast — bỏ qua */ }
            catch (ObjectDisposedException) { }
        }

        // ==================== NHẬN ====================

        private async Task ReceiveLoopAsync(Socket socket)
        {
            byte[] buf = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    var r = await socket.ReceiveFromAsync(buf, SocketFlags.None, any, _cts.Token).ConfigureAwait(false);
                    Handle(buf.AsSpan(0, r.ReceivedBytes), (IPEndPoint)r.RemoteEndPoint);
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (SocketException) { /* mạng chớp — vòng sau */ }
                catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Discovery] {ex.Message}"); }
            }
        }

        private void Handle(ReadOnlySpan<byte> data, IPEndPoint from)
        {
            if (data.Length < Magic.Length + 2 || !data.StartsWith(Magic)) return; // gói lạ → im lặng bỏ
            byte type = data[Magic.Length];
            Msg? m;
            try { m = JsonSerializer.Deserialize<Msg>(data[(Magic.Length + 1)..]); }
            catch (JsonException) { return; }
            if (m is null || m.I == Guid.Empty || m.I == _instance) return; // gói của chính mình (loopback)
            if (string.IsNullOrEmpty(m.F) || m.F.Length > 32 || m.F == _fingerprint) return;
            if (m.P is <= 0 or > 65535) return;

            if (type == TBye)
            {
                if (_peers.TryGetValue(m.F, out var p) && p.Instance == m.I && _peers.TryRemove(m.F, out _))
                    Raise(PeerLost, p);
                return;
            }
            if (type is not (TAnnounce or TQuery or TReply)) return;

            string name = new string((m.N ?? "").Where(c => !char.IsControl(c)).Take(64).ToArray());
            var ep = new IPEndPoint(from.Address, m.P);
            bool isNew = false, changed = false;

            var peer = _peers.AddOrUpdate(m.F,
                _ => { isNew = true; return new DiscoveredPeer(m.I, m.F, name, ep); },
                (_, old) =>
                {
                    if (old.Instance != m.I || !old.TcpEndPoint.Equals(ep) || old.Name != name)
                    {
                        changed = true;
                        return new DiscoveredPeer(m.I, m.F, name, ep);
                    }
                    old.LastSeenUtc = DateTime.UtcNow;
                    return old;
                });

            if (isNew || changed) Raise(PeerSeen, peer);

            // Trả lời UNICAST: người hỏi (Query) hoặc người mới (Announce đầu tiên) biết đến mình ngay
            if (type == TQuery || (type == TAnnounce && isNew))
            {
                long now = Environment.TickCount64;
                long last = _lastReplyTick.GetOrAdd(m.I, 0);
                if (now - last >= 500 && _unicast is not null)
                {
                    _lastReplyTick[m.I] = now;
                    lock (_sendLock) TrySend(BuildPacket(TReply), from);
                }
            }
        }

        // ==================== PRESENCE ====================

        private async Task PresenceLoopAsync()
        {
            try
            {
                // Bùng nổ lúc khởi động (0s, 0.4s, 1.2s) để vào danh sách của mọi người thật nhanh
                Broadcast(TAnnounce);
                await Task.Delay(400, _cts.Token).ConfigureAwait(false);
                Broadcast(TQuery);
                await Task.Delay(800, _cts.Token).ConfigureAwait(false);
                Broadcast(TAnnounce);

                var rng = new Random();
                DateTime nextAnnounce = DateTime.UtcNow + AnnounceInterval;
                while (!_cts.IsCancellationRequested)
                {
                    await Task.Delay(1000, _cts.Token).ConfigureAwait(false);

                    if (DateTime.UtcNow >= nextAnnounce)
                    {
                        Broadcast(TAnnounce);
                        // jitter ±0.75s: nhiều máy bật cùng lúc không bắn trùng nhịp
                        nextAnnounce = DateTime.UtcNow + AnnounceInterval + TimeSpan.FromMilliseconds(rng.Next(-750, 750));
                    }

                    foreach (var (fp, p) in _peers)
                        if (DateTime.UtcNow - p.LastSeenUtc > PeerTtl && _peers.TryRemove(fp, out var gone))
                            Raise(PeerLost, gone);
                }
            }
            catch (OperationCanceledException) { }
        }

        // ==================== ĐỔI MẠNG ====================

        private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
            => OnNetworkAddressChanged(sender, EventArgs.Empty);

        /// <summary>Cắm/rút cáp, đổi Wi-Fi, DHCP cấp IP mới → dò lại card mạng, join lại
        /// multicast và announce ngay (gom nhiều sự kiện liên tiếp thành một lần xử lý).</summary>
        private void OnNetworkAddressChanged(object? sender, EventArgs e)
        {
            if (Interlocked.Exchange(ref _netChangePending, 1) == 1) return;
            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(1500, _cts.Token).ConfigureAwait(false);
                    Interlocked.Exchange(ref _netChangePending, 0);
                    _interfaces = EnumerateInterfaces();
                    JoinMulticast();
                    try { NetworkChanged?.Invoke(); } catch { }
                    Broadcast(TAnnounce);
                    await Task.Delay(500, _cts.Token).ConfigureAwait(false);
                    Broadcast(TQuery);
                }
                catch (OperationCanceledException) { }
            });
        }

        public static IReadOnlyList<LocalInterface> EnumerateInterfaces()
        {
            var list = new List<LocalInterface>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

                    IPInterfaceProperties props;
                    try { props = ni.GetIPProperties(); } catch { continue; }
                    bool hasGw = props.GatewayAddresses.Any(g =>
                        g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
                    int index = -1;
                    try { index = props.GetIPv4Properties()?.Index ?? -1; } catch { }

                    foreach (var ua in props.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        IPAddress mask = ua.IPv4Mask ?? IPAddress.Any;
                        IPAddress? bcast = null;
                        byte[] ip = ua.Address.GetAddressBytes(), mk = mask.GetAddressBytes();
                        if (!mask.Equals(IPAddress.Any) && !mask.Equals(IPAddress.Broadcast))
                        {
                            var b = new byte[4];
                            for (int i = 0; i < 4; i++) b[i] = (byte)(ip[i] | ~mk[i]);
                            bcast = new IPAddress(b);
                        }
                        list.Add(new LocalInterface(ni.Name, ni.NetworkInterfaceType, ua.Address, mask, bcast, hasGw, index));
                    }
                }
            }
            catch (NetworkInformationException) { }

            // Sắp xếp: có gateway trước, card vật lý (Ethernet/Wi-Fi) trước card ảo, APIPA cuối
            return list.OrderByDescending(i => i.HasGateway)
                       .ThenBy(i => IsVirtual(i.Name) ? 1 : 0)
                       .ThenBy(i => i.Address.ToString().StartsWith("169.254.") ? 1 : 0)
                       .ToList();
        }

        private static bool IsVirtual(string name)
        {
            string n = name.ToLowerInvariant();
            return n.Contains("vethernet") || n.Contains("virtual") || n.Contains("vmware") ||
                   n.Contains("vbox") || n.Contains("hyper-v") || n.Contains("wsl") || n.Contains("docker");
        }

        private static void Raise(Action<DiscoveredPeer>? ev, DiscoveredPeer p)
        {
            try { ev?.Invoke(p); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Discovery event] {ex}"); }
        }

        public void Dispose()
        {
            if (_cts.IsCancellationRequested) return;
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
            NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
            try { Broadcast(TBye); } catch { }
            _cts.Cancel();
            try { _shared?.Dispose(); } catch { }
            try { _unicast?.Dispose(); } catch { }
        }
    }
}
