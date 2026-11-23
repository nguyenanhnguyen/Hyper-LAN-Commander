using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp
{
    /// <summary>Thông tin một phiên đã XÁC THỰC với một peer.</summary>
    public sealed record PeerSessionInfo(
        string Fingerprint,
        string Name,
        byte[] PublicKey,
        IPEndPoint RemoteEndPoint,
        int ListenPort,
        string SessionId,
        bool IsInitiator,
        Guid Instance)
    {
        public IPEndPoint ListenEndPoint => new(RemoteEndPoint.Address, ListenPort);
    }

    /// <summary>Một sự kiện ở tầng dây cho Protocol Inspector.</summary>
    public sealed record FrameTrace(
        DateTime Time,
        long ConnectionId,
        string Peer,
        bool Outgoing,
        string Kind,          // "Hello" / "Sealed" / "KEY" / "AUTH" / "CLOSE"
        PacketType? Inner,    // loại gói thật (chỉ người trong cuộc biết)
        int WireBytes,
        ulong? Sequence,      // nonce counter của AES-GCM
        string CipherHex,     // 16 byte đầu trên dây — đúng thứ kẻ nghe lén nhìn thấy
        string Note,
        int Aggregated = 1);  // >1: gộp nhiều FileChunk để không ngập UI

    public enum CloseReason { Closed, PeerLeft, Timeout, NetworkError, Tampered, ProtocolError, AuthFailed, Replaced, SelfConnection, Shutdown }

    /// <summary>Không có/mất đường tới peer. Là IOException → tầng trên coi là lỗi mạng tạm thời.</summary>
    public sealed class PeerUnavailableException : IOException
    {
        public CloseReason Reason { get; }
        public PeerUnavailableException(string message, CloseReason reason = CloseReason.NetworkError)
            : base(message) => Reason = reason;
    }

    /// <summary>
    /// TCP messaging đa kết nối, MÃ HÓA ĐẦU-CUỐI, định danh theo DANH TÍNH (fingerprint).
    ///
    /// • Peer được gọi bằng fingerprint, không phải ip:port. Peer đổi IP (DHCP, đổi Wi-Fi)
    ///   vẫn là cùng một người: lịch sử chat và transfer đang dở đi theo danh tính.
    /// • "Sổ địa chỉ" mỗi peer (từ discovery + phiên trước) → tự kết nối lại khi cần gửi.
    ///   Có nhiều địa chỉ thì đua kết nối song song kiểu Happy Eyeballs (RFC 8305).
    /// • Mỗi kết nối có MỘT writer loop với 2 hàng đợi ưu tiên: điều khiển (chat, ping,
    ///   offer...) luôn chen trước dữ liệu khối (chunk file) — chat vẫn tức thì khi đang
    ///   đẩy file GB, giống stream priority của HTTP/2. Hàng bulk có giới hạn → backpressure.
    /// • Heartbeat 3s + TCP keepalive: peer rút dây mạng bị phát hiện trong ~12s thay vì treo vô hạn.
    /// • Hai bên kết nối cho nhau CÙNG LÚC → quy tắc tie-break tất định giữ đúng 1 kết nối.
    /// </summary>
    public sealed class MessagingService : IDisposable
    {
        public const int DefaultPort = 8889;

        private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(6);
        private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(3);
        private static readonly TimeSpan HappyEyeballsDelay = TimeSpan.FromMilliseconds(250);
        private const int PingIntervalMs = 3000;
        private const int DeadAfterMs = 12000;
        private const int BulkQueueDepth = 8;
        private const int MaxConnections = 64;
        private const int MaxTextBytes = 64 * 1024;

        private readonly CryptoService _crypto;
        private readonly string _localName;
        private readonly int _preferredPort;
        private TcpListener? _listener;
        private readonly CancellationTokenSource _cts = new();

        private readonly object _sessionLock = new();
        private readonly Dictionary<string, Connection> _sessions = new();      // fp → kết nối đang dùng
        private readonly ConcurrentDictionary<long, Connection> _all = new();   // mọi kết nối (kể cả đang bắt tay)
        private readonly ConcurrentDictionary<string, EndpointBook> _books = new();
        private readonly object _dialLock = new();
        private readonly Dictionary<string, Task<Connection>> _dialing = new();
        private long _nextConnId;
        private long _bytesSent, _bytesReceived;

        public Guid InstanceId { get; } = Guid.NewGuid();
        public int ListenPort { get; private set; }
        public string LocalFingerprint => _crypto.Fingerprint;
        public long BytesSent => Interlocked.Read(ref _bytesSent);
        public long BytesReceived => Interlocked.Read(ref _bytesReceived);
        public int SessionCount { get { lock (_sessionLock) return _sessions.Count; } }

        // ---------- Events (bắn trên thread nền — UI tự marshal) ----------
        public event Action<PeerSessionInfo>? SessionEstablished;
        public event Action<string, CloseReason>? SessionLost;              // fp, lý do
        public event Action<string, int>? RttUpdated;                       // fp, ms
        public event Action<string, string>? TextReceived;                  // fp, text
        public event Action<string, CloseReason, string>? ConnectionRejected; // endpoint, lý do, chi tiết

        /// <summary>Handler theo loại gói (file, link-test...). Được AWAIT trong vòng đọc → tự tạo
        /// backpressure. Payload chỉ hợp lệ trong lúc gọi (buffer được tái sử dụng).
        /// KHÔNG được await việc GỬI bên trong handler (dùng fire-and-forget) để tránh deadlock.</summary>
        public delegate ValueTask FrameHandlerFn(string fingerprint, PacketType type, ReadOnlyMemory<byte> payload);

        private readonly ConcurrentDictionary<PacketType, FrameHandlerFn> _handlers = new();

        public void RegisterHandler(FrameHandlerFn handler, params PacketType[] types)
        {
            foreach (var t in types) _handlers[t] = handler;
        }

        public void UnregisterHandler(params PacketType[] types)
        {
            foreach (var t in types) _handlers.TryRemove(t, out _);
        }

        // ---------- Protocol Inspector ----------
        /// <summary>Bật để nhận FrameTraced cho từng record (tốn chút CPU — chỉ bật khi Inspector mở).</summary>
        public bool TraceEnabled { get; set; }
        public event Action<FrameTrace>? FrameTraced;

        private readonly IPAddress? _bindAddress;

        /// <param name="bindAddress">null = mọi card mạng (dual-stack). Attack Lab dùng 127.0.0.1 để không lộ ra LAN.</param>
        public MessagingService(CryptoService crypto, string localName, int preferredPort = DefaultPort,
                                IPAddress? bindAddress = null)
        {
            _crypto = crypto;
            _localName = localName.Length > 64 ? localName[..64] : localName;
            _preferredPort = preferredPort;
            _bindAddress = bindAddress;
        }

        // =====================================================================
        //  LISTENER
        // =====================================================================

        public void Start()
        {
            _listener = CreateListener(_preferredPort, _bindAddress, out int port);
            ListenPort = port;
            _ = Task.Run(AcceptLoopAsync);
        }

        /// <summary>
        /// Socket dual-stack (IPv6 + IPv4-mapped) nếu hệ thống hỗ trợ. Cổng bị chiếm
        /// (instance khác đang chạy) → thử các cổng kế tiếp; discovery sẽ quảng bá cổng THẬT.
        /// </summary>
        private static TcpListener CreateListener(int preferred, IPAddress? bind, out int actualPort)
        {
            var candidates = (preferred == 0 ? Enumerable.Empty<int>() : Enumerable.Range(preferred, 12))
                             .Where(p => p < 65536).Append(0);
            foreach (int port in candidates)
            {
                foreach (bool dual in new[] { true, false })
                {
                    if (dual && (!Socket.OSSupportsIPv6 || bind is not null)) continue;
                    TcpListener? l = null;
                    try
                    {
                        l = bind is not null ? new TcpListener(bind, port)
                          : dual ? new TcpListener(IPAddress.IPv6Any, port) : new TcpListener(IPAddress.Any, port);
                        if (dual) l.Server.DualMode = true;
                        l.Server.ExclusiveAddressUse = true;
                        l.Start(backlog: 64);
                        actualPort = ((IPEndPoint)l.LocalEndpoint).Port;
                        return l;
                    }
                    catch (SocketException)
                    {
                        l?.Stop();
                    }
                }
            }
            throw new IOException("Không mở được cổng TCP nào để lắng nghe");
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await _listener!.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
                    if (!AdmitConnection(client))
                    {
                        Interlocked.Increment(ref _refusedFlood);
                        client.Client.LingerState = new LingerOption(true, 0); // RST ngay, không giữ TIME_WAIT
                        client.Dispose();
                        continue;
                    }
                    StartConnection(client, isInitiator: false);
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[TCP accept] {ex.Message}");
                    try { await Task.Delay(200, _cts.Token).ConfigureAwait(false); } catch { break; }
                }
            }
        }

        private const int MaxPendingPerIp = 16;
        private long _refusedFlood;
        /// <summary>Số kết nối bị từ chối ngay ở cửa (flood / quá hạn mức mỗi IP).</summary>
        public long RefusedConnections => Interlocked.Read(ref _refusedFlood);

        /// <summary>
        /// Kiểm soát cửa vào (chống connection-flood / slowloris):
        ///  • tổng tối đa 64 kết nối;
        ///  • mỗi IP tối đa 16 kết nối CHƯA xác thực — một máy tấn công không thể chiếm hết chỗ
        ///    và khóa người dùng hợp lệ ở máy khác. Kết nối chưa bắt tay xong bị đá sau 6s.
        /// </summary>
        private bool AdmitConnection(TcpClient client)
        {
            if (_all.Count >= MaxConnections) return false;
            if (client.Client.RemoteEndPoint is not IPEndPoint rep) return false;
            var ip = Normalize(rep).Address;
            int pending = _all.Values.Count(c => !c.Authenticated.Task.IsCompleted && c.Remote.Address.Equals(ip));
            return pending < MaxPendingPerIp;
        }

        // =====================================================================
        //  SỔ ĐỊA CHỈ (fingerprint → các endpoint đã biết)
        // =====================================================================

        private sealed class EndpointBook
        {
            private readonly Dictionary<IPEndPoint, DateTime> _eps = new();
            public void Add(IPEndPoint ep) { lock (_eps) _eps[ep] = DateTime.UtcNow; }
            public void Remove(IPEndPoint ep) { lock (_eps) _eps.Remove(ep); }
            public List<IPEndPoint> Snapshot()
            {
                lock (_eps)
                {
                    foreach (var old in _eps.Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromHours(12))
                                            .Select(kv => kv.Key).ToList())
                        _eps.Remove(old);
                    return _eps.OrderByDescending(kv => kv.Value).Select(kv => kv.Key).Take(6).ToList();
                }
            }
        }

        /// <summary>Thêm một đường tới peer (từ discovery, từ phiên cũ, từ danh bạ).</summary>
        public void AddEndpoint(string fingerprint, IPEndPoint endpoint)
        {
            if (fingerprint == _crypto.Fingerprint) return;
            _books.GetOrAdd(fingerprint, _ => new EndpointBook()).Add(Normalize(endpoint));
        }

        public bool IsConnected(string fingerprint) => GetActive(fingerprint) is not null;

        public PeerSessionInfo? GetSession(string fingerprint) => GetActive(fingerprint)?.Info;

        public int GetRtt(string fingerprint) => GetActive(fingerprint)?.RttMs ?? -1;

        private Connection? GetActive(string fp)
        {
            lock (_sessionLock)
                return _sessions.TryGetValue(fp, out var c) && c.AcceptsWrites ? c : null;
        }

        // =====================================================================
        //  API GỬI
        // =====================================================================

        public Task SendTextAsync(string fingerprint, string text, CancellationToken ct = default)
        {
            byte[] data = Encoding.UTF8.GetBytes(text);
            if (data.Length > MaxTextBytes) throw new ArgumentException("Tin nhắn quá dài");
            return SendAsync(fingerprint, PacketType.Text, data, ct);
        }

        /// <summary>Gửi gói ĐIỀU KHIỂN (ưu tiên cao). Hoàn tất khi gói đã được ghi xuống socket.
        /// Tự kết nối (lại) nếu chưa có phiên.</summary>
        public async Task SendAsync(string fingerprint, PacketType type, ReadOnlyMemory<byte> payload,
                                    CancellationToken ct = default)
        {
            byte[] copy = payload.ToArray();
            for (int attempt = 0; ; attempt++)
            {
                Connection conn = await GetSessionAsync(fingerprint, ct).ConfigureAwait(false);
                var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                if (!TryEnqueueHigh(conn, new OutFrame(type, copy, 0, copy.Length, false, done)))
                {
                    if (attempt < 3) continue; // phiên vừa bị thay thế → lấy phiên mới
                    throw new PeerUnavailableException("Phiên đã đóng");
                }
                await done.Task.WaitAsync(ct).ConfigureAwait(false);
                return;
            }
        }

        /// <summary>
        /// Gửi gói DỮ LIỆU KHỐI (chunk file). NHẬN QUYỀN SỞ HỮU <paramref name="pooledBuffer"/>
        /// (thuê từ ArrayPool) — writer loop trả lại pool sau khi ghi. Chờ khi hàng bulk đầy
        /// (backpressure) nên bên gửi không bao giờ đọc file nhanh hơn mạng chuyển được.
        /// </summary>
        public async ValueTask SendBulkAsync(string fingerprint, PacketType type, byte[] pooledBuffer, int count,
                                             CancellationToken ct = default)
        {
            bool owned = true;
            try
            {
                for (int attempt = 0; ; attempt++)
                {
                    Connection conn = await GetSessionAsync(fingerprint, ct).ConfigureAwait(false);
                    ct.ThrowIfCancellationRequested();
                    if (await TryEnqueueBulkAsync(conn, new OutFrame(type, pooledBuffer, 0, count, true, null))
                            .ConfigureAwait(false))
                    {
                        owned = false;
                        return;
                    }
                    if (attempt >= 3) throw new PeerUnavailableException("Phiên đã đóng");
                }
            }
            finally
            {
                if (owned) ArrayPool<byte>.Shared.Return(pooledBuffer);
            }
        }

        /// <summary>Kết nối thủ công tới host:port. Trả về phiên đã xác thực.</summary>
        public async Task<PeerSessionInfo> ConnectAsync(string host, int port, CancellationToken ct = default)
        {
            IPAddress[] addrs = IPAddress.TryParse(host, out IPAddress? ip)
                ? new[] { ip }
                : await Dns.GetHostAddressesAsync(host, ct).ConfigureAwait(false);
            var eps = addrs.Where(a => a.AddressFamily == AddressFamily.InterNetwork ||
                                       (a.AddressFamily == AddressFamily.InterNetworkV6 && Socket.OSSupportsIPv6))
                           .Select(a => new IPEndPoint(a, port)).ToList();
            if (eps.Count == 0) throw new PeerUnavailableException($"Không phân giải được {host}");

            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
            TcpClient client = await RaceConnectAsync(eps, linked.Token).ConfigureAwait(false);
            Connection conn = StartConnection(client, isInitiator: true);
            return await conn.Authenticated.Task.WaitAsync(HandshakeTimeout, linked.Token).ConfigureAwait(false);
        }

        // =====================================================================
        //  QUAY SỐ (dial) — single-flight + Happy Eyeballs
        // =====================================================================

        private async Task<Connection> GetSessionAsync(string fp, CancellationToken ct)
        {
            if (GetActive(fp) is { } active) return active;

            Task<Connection> dial;
            lock (_dialLock)
            {
                if (!_dialing.TryGetValue(fp, out dial!))
                {
                    // Task.Run: đảm bảo task được đăng ký vào _dialing TRƯỚC khi có thể hoàn tất
                    dial = Task.Run(() => DialAsync(fp));
                    _dialing[fp] = dial;
                }
            }
            return await dial.WaitAsync(ct).ConfigureAwait(false);
        }

        private async Task<Connection> DialAsync(string fp)
        {
            try
            {
                if (GetActive(fp) is { } active) return active; // phiên vừa được bên kia mở tới

                var book = _books.TryGetValue(fp, out var b) ? b.Snapshot() : new List<IPEndPoint>();
                if (book.Count == 0)
                    throw new PeerUnavailableException("Chưa biết địa chỉ của peer này (offline?)");

                var remaining = book.ToList();
                while (remaining.Count > 0)
                {
                    TcpClient client = await RaceConnectAsync(remaining, _cts.Token).ConfigureAwait(false);
                    var ep = Normalize((IPEndPoint)client.Client.RemoteEndPoint!);
                    remaining.RemoveAll(e => e.Equals(ep));

                    Connection conn = StartConnection(client, isInitiator: true);
                    PeerSessionInfo info;
                    try
                    {
                        info = await conn.Authenticated.Task.WaitAsync(HandshakeTimeout, _cts.Token)
                                         .ConfigureAwait(false);
                    }
                    catch (Exception) when (remaining.Count > 0) { continue; }

                    if (info.Fingerprint != fp)
                    {
                        // Địa chỉ này giờ là của một danh tính KHÁC (IP bị tái cấp phát, hoặc gói
                        // discovery giả mạo) — phiên kia vẫn hợp lệ, nhưng không phải người ta cần.
                        if (_books.TryGetValue(fp, out var bk)) bk.Remove(ep);
                        continue;
                    }
                    return GetActive(fp) ?? conn;
                }
                throw new PeerUnavailableException("Không địa chỉ nào của peer phản hồi");
            }
            finally
            {
                lock (_dialLock) _dialing.Remove(fp);
            }
        }

        /// <summary>
        /// Happy Eyeballs (RFC 8305): thử endpoint đầu tiên, cứ mỗi 250ms chưa xong lại mở
        /// thêm một hướng song song. Ai bắt tay TCP xong trước thắng, các hướng khác bị hủy.
        /// Peer có cả Wi-Fi lẫn Ethernet (hoặc một IP đã chết) vẫn kết nối gần như tức thì.
        /// </summary>
        private static async Task<TcpClient> RaceConnectAsync(IReadOnlyList<IPEndPoint> endpoints, CancellationToken ct)
        {
            using var race = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var attempts = new List<Task<TcpClient>>();
            Exception? last = null;

            for (int i = 0; i < endpoints.Count; i++)
                attempts.Add(AttemptAsync(endpoints[i], HappyEyeballsDelay * i, race.Token));

            while (attempts.Count > 0)
            {
                Task<TcpClient> done = await Task.WhenAny(attempts).ConfigureAwait(false);
                attempts.Remove(done);
                if (done.IsCompletedSuccessfully)
                {
                    race.Cancel();
                    foreach (var loser in attempts)
                        _ = loser.ContinueWith(t => { if (t.IsCompletedSuccessfully) t.Result.Dispose(); },
                                               TaskScheduler.Default);
                    return done.Result;
                }
                last = done.Exception?.InnerException ?? last;
            }
            ct.ThrowIfCancellationRequested();
            throw new PeerUnavailableException($"Không kết nối được: {last?.Message}");
        }

        private static async Task<TcpClient> AttemptAsync(IPEndPoint ep, TimeSpan delay, CancellationToken ct)
        {
            if (delay > TimeSpan.Zero) await Task.Delay(delay, ct).ConfigureAwait(false);
            var client = new TcpClient(ep.AddressFamily);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ConnectTimeout);
            try
            {
                await client.ConnectAsync(ep, timeout.Token).ConfigureAwait(false);
                return client;
            }
            catch
            {
                client.Dispose();
                throw;
            }
        }

        // =====================================================================
        //  KẾT NỐI
        // =====================================================================

        private readonly record struct OutFrame(PacketType Type, byte[] Buffer, int Offset, int Count,
                                                bool ReturnToPool, TaskCompletionSource? Done);

        private sealed class Connection
        {
            public required long Id { get; init; }
            public required TcpClient Client { get; init; }
            public required NetworkStream Stream { get; init; }
            public required bool IsInitiator { get; init; }
            public required IPEndPoint Remote { get; init; }
            public required byte[] MyHello { get; init; }
            public required ECDiffieHellman Ephemeral { get; init; }

            public readonly CancellationTokenSource Cts = new();
            public readonly TaskCompletionSource KeysReady = new(TaskCreationOptions.RunContinuationsAsynchronously);
            public readonly TaskCompletionSource<PeerSessionInfo> Authenticated =
                new(TaskCreationOptions.RunContinuationsAsynchronously);

            // Hàng đợi ưu tiên 2 mức: _items đếm tổng số gói, _bulkSlots giới hạn hàng bulk
            public readonly ConcurrentQueue<OutFrame> High = new();
            public readonly ConcurrentQueue<OutFrame> Bulk = new();
            public readonly SemaphoreSlim Items = new(0);
            public readonly SemaphoreSlim BulkSlots = new(BulkQueueDepth);

            public CipherState? Tx, Rx;
            public byte[]? Transcript;
            public HelloMsg? PeerHello;
            public string? Fingerprint;
            public PeerSessionInfo? Info;
            public Task? WriterTask;

            public long LastRxTick = Environment.TickCount64;
            public volatile int RttMs = -1;
            // Inspector: gộp record dữ liệu khối (mỗi chiều một bộ đếm, chỉ 1 thread chạm vào)
            public int TxAgg, RxAgg;
            public long TxAggBytes, RxAggBytes, TxAggTick, RxAggTick;
            public volatile bool Draining;   // đang đóng êm: không nhận gói mới
            public int ClosedFlag;
            public CloseReason Reason = CloseReason.Closed;

            public bool IsClosed => Volatile.Read(ref ClosedFlag) == 1;
            public bool AcceptsWrites => !IsClosed && !Draining && Authenticated.Task.IsCompletedSuccessfully;
        }

        private Connection StartConnection(TcpClient client, bool isInitiator)
        {
            ConfigureSocket(client.Client);
            var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var hello = new HelloMsg(Protocol.Magic, Protocol.Version, _crypto.PublicKey,
                eph.ExportSubjectPublicKeyInfo(), RandomNumberGenerator.GetBytes(Handshake.NonceSize),
                _localName, ListenPort, InstanceId);

            var conn = new Connection
            {
                Id = Interlocked.Increment(ref _nextConnId),
                Client = client,
                Stream = client.GetStream(),
                IsInitiator = isInitiator,
                Remote = Normalize((IPEndPoint)client.Client.RemoteEndPoint!),
                MyHello = JsonSerializer.SerializeToUtf8Bytes(hello),
                Ephemeral = eph,
            };
            _all[conn.Id] = conn;
            _ = conn.Authenticated.Task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);

            conn.WriterTask = Task.Run(() => WriterLoopAsync(conn));
            _ = Task.Run(() => ReaderLoopAsync(conn));
            _ = Task.Run(() => HeartbeatLoopAsync(conn));
            return conn;
        }

        private static void ConfigureSocket(Socket s)
        {
            s.NoDelay = true; // tắt Nagle: chat/ping không bị gom chờ 200ms
            try
            {
                // TCP keepalive ở tầng OS: phát hiện peer biến mất cả khi app không gửi gì
                s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 15);
                s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 3);
                s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 3);
            }
            catch (SocketException) { /* OS cũ — heartbeat tầng app vẫn lo được */ }
        }

        private static IPEndPoint Normalize(IPEndPoint ep)
            => ep.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(ep.Address.MapToIPv4(), ep.Port) : ep;

        // ---------------- Hàng đợi ----------------

        private static bool TryEnqueueHigh(Connection c, OutFrame f, bool allowBeforeAuth = false)
        {
            if (c.IsClosed || c.Draining || (!allowBeforeAuth && !c.Authenticated.Task.IsCompletedSuccessfully))
                return false;
            c.High.Enqueue(f);
            c.Items.Release();
            if (c.IsClosed) DrainQueues(c); // đóng đúng lúc vừa enqueue → không để gói nào treo
            return true;
        }

        private static async ValueTask<bool> TryEnqueueBulkAsync(Connection c, OutFrame f)
        {
            if (!c.AcceptsWrites) return false;
            try { await c.BulkSlots.WaitAsync(c.Cts.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { return false; }
            if (!c.AcceptsWrites) { c.BulkSlots.Release(); return false; }
            c.Bulk.Enqueue(f);
            c.Items.Release();
            if (c.IsClosed) DrainQueues(c);
            return true;
        }

        private static void DrainQueues(Connection c)
        {
            var ex = new PeerUnavailableException("Kết nối đã đóng", c.Reason);
            while (c.High.TryDequeue(out var f)) Fail(f, ex);
            while (c.Bulk.TryDequeue(out var f)) Fail(f, ex);

            static void Fail(OutFrame f, Exception ex)
            {
                f.Done?.TrySetException(ex);
                if (f.ReturnToPool) ArrayPool<byte>.Shared.Return(f.Buffer);
            }
        }

        // ---------------- Writer loop ----------------

        private async Task WriterLoopAsync(Connection c)
        {
            CancellationToken ct = c.Cts.Token;
            try
            {
                // 1) Hello dạng rõ — gửi ngay, KHÔNG chờ bên kia (bắt tay song song, 1-RTT)
                byte[] hello = new byte[Protocol.HeaderSize + c.MyHello.Length];
                Protocol.WriteHeader(hello, RecordType.Hello, c.MyHello.Length);
                c.MyHello.CopyTo(hello, Protocol.HeaderSize);
                await c.Stream.WriteAsync(hello, ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesSent, hello.Length);
                if (TraceEnabled)
                    Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), true, "Hello", null, hello.Length, null,
                        Convert.ToHexString(c.MyHello, 0, Math.Min(16, c.MyHello.Length)),
                        $"Hello · Id={_crypto.Fingerprint} · Eph=P-256 (ephemeral) · Nonce=32B · PLAINTEXT (public values only)"));

                // 2) Chờ có khóa phiên, sau đó mọi thứ đều Sealed
                await c.KeysReady.Task.WaitAsync(ct).ConfigureAwait(false);

                while (true)
                {
                    await c.Items.WaitAsync(ct).ConfigureAwait(false);
                    OutFrame f;
                    if (c.High.TryDequeue(out f)) { }
                    else if (c.Bulk.TryDequeue(out f)) c.BulkSlots.Release();
                    else
                    {
                        if (!c.Draining) continue;
                        // Hết hàng + đang đóng êm → gửi Bye, đóng chiều ghi (FIN), để reader nhận nốt
                        await WriteSealedAsync(c, new OutFrame(PacketType.Bye, Array.Empty<byte>(), 0, 0, false, null), ct)
                            .ConfigureAwait(false);
                        try { c.Client.Client.Shutdown(SocketShutdown.Send); } catch { }
                        return;
                    }
                    await WriteSealedAsync(c, f, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Close(c, c.Draining ? CloseReason.Closed : ClassifyIo(ex));
            }
            finally
            {
                DrainQueues(c);
                c.Tx?.Dispose();
            }
        }

        /// <summary>
        /// [1B 'S'][4B len][ AES-GCM( 1B PacketType ‖ payload ) ][16B tag]
        /// Mã hóa tại chỗ trong MỘT buffer thuê từ pool → một lần WriteAsync = một lời gọi hệ thống.
        /// </summary>
        private async ValueTask WriteSealedAsync(Connection c, OutFrame f, CancellationToken ct)
        {
            int plainLen = 1 + f.Count;
            int bodyLen = plainLen + Protocol.TagSize;
            int total = Protocol.HeaderSize + bodyLen;
            byte[] buf = ArrayPool<byte>.Shared.Rent(total);
            try
            {
                Protocol.WriteHeader(buf, RecordType.Sealed, bodyLen);
                buf[Protocol.HeaderSize] = (byte)f.Type;
                f.Buffer.AsSpan(f.Offset, f.Count).CopyTo(buf.AsSpan(Protocol.HeaderSize + 1));
                ulong seq = c.Tx!.Counter;
                c.Tx.SealInPlace(buf.AsSpan(Protocol.HeaderSize, plainLen),
                                 buf.AsSpan(Protocol.HeaderSize + plainLen, Protocol.TagSize),
                                 buf.AsSpan(0, Protocol.HeaderSize)); // AAD = header
                await c.Stream.WriteAsync(buf.AsMemory(0, total), ct).ConfigureAwait(false);
                Interlocked.Add(ref _bytesSent, total);
                f.Done?.TrySetResult();
                if (TraceEnabled)
                    TraceSealed(c, true, f.Type, total, seq, buf.AsSpan(Protocol.HeaderSize, bodyLen), f.Count,
                                ref c.TxAgg, ref c.TxAggBytes, ref c.TxAggTick);
            }
            catch (Exception ex)
            {
                f.Done?.TrySetException(new PeerUnavailableException(ex.Message));
                throw;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
                if (f.ReturnToPool) ArrayPool<byte>.Shared.Return(f.Buffer);
            }
        }

        // ---------------- Reader loop ----------------

        private async Task ReaderLoopAsync(Connection c)
        {
            CancellationToken ct = c.Cts.Token;
            byte[] header = new byte[Protocol.HeaderSize];
            byte[] wirePreview = new byte[16];
            CloseReason reason = CloseReason.Closed;
            try
            {
                // ===== Bắt tay (có hạn chót — kẻ mở kết nối rồi im lặng sẽ bị đá) =====
                using (var hs = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    hs.CancelAfter(HandshakeTimeout);

                    var (type, len) = await Protocol.ReadHeaderAsync(c.Stream, header, hs.Token).ConfigureAwait(false);
                    if (type != RecordType.Hello || len > Protocol.MaxHelloSize)
                        throw new HlcProtocolException("Gói đầu tiên phải là Hello");
                    byte[] helloBytes = new byte[len];
                    await c.Stream.ReadExactlyAsync(helloBytes, hs.Token).ConfigureAwait(false);
                    Interlocked.Add(ref _bytesReceived, Protocol.HeaderSize + len);
                    ProcessHello(c, helloBytes);

                    (type, len) = await Protocol.ReadHeaderAsync(c.Stream, header, hs.Token).ConfigureAwait(false);
                    if (type != RecordType.Sealed || len < 1 + Protocol.TagSize || len > Protocol.MaxHelloSize)
                        throw new HlcProtocolException("Thiếu gói Auth");
                    byte[] auth = new byte[len];
                    await c.Stream.ReadExactlyAsync(auth, hs.Token).ConfigureAwait(false);
                    Interlocked.Add(ref _bytesReceived, Protocol.HeaderSize + len);
                    int plain = len - Protocol.TagSize;
                    string authHex = Convert.ToHexString(auth, 0, Math.Min(16, len));
                    c.Rx!.OpenInPlace(auth.AsSpan(0, plain), auth.AsSpan(plain, Protocol.TagSize), header);
                    if ((PacketType)auth[0] != PacketType.Auth)
                        throw new HlcProtocolException("Gói Sealed đầu tiên phải là Auth");
                    VerifyAuth(c, auth.AsSpan(1, plain - 1));
                    if (TraceEnabled)
                        Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), false, "AUTH", PacketType.Auth,
                            Protocol.HeaderSize + len, 0, authHex,
                            $"ECDSA-P256 signature over transcript ✓ · decrypted with fresh key (key confirmation) · identity {c.Fingerprint}"));
                }
                OnAuthenticated(c);

                // ===== Vòng nhận chính =====
                while (true)
                {
                    var (type, len) = await Protocol.ReadHeaderAsync(c.Stream, header, ct).ConfigureAwait(false);
                    if (type != RecordType.Sealed || len < 1 + Protocol.TagSize)
                        throw new HlcProtocolException($"Record không hợp lệ: {type}");

                    byte[] buf = ArrayPool<byte>.Shared.Rent(len);
                    try
                    {
                        await c.Stream.ReadExactlyAsync(buf.AsMemory(0, len), ct).ConfigureAwait(false);
                        c.LastRxTick = Environment.TickCount64;
                        Interlocked.Add(ref _bytesReceived, Protocol.HeaderSize + len);

                        int plain = len - Protocol.TagSize;
                        ulong seq = c.Rx!.Counter;
                        bool tracing = TraceEnabled;
                        if (tracing) Buffer.BlockCopy(buf, 0, wirePreview, 0, Math.Min(16, len));
                        c.Rx.OpenInPlace(buf.AsSpan(0, plain), buf.AsSpan(plain, Protocol.TagSize), header);
                        if (tracing)
                            TraceSealed(c, false, (PacketType)buf[0], Protocol.HeaderSize + len, seq,
                                        wirePreview.AsSpan(0, Math.Min(16, len)), plain - 1,
                                        ref c.RxAgg, ref c.RxAggBytes, ref c.RxAggTick);
                        await DispatchAsync(c, (PacketType)buf[0], buf.AsMemory(1, plain - 1)).ConfigureAwait(false);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(buf);
                    }
                }
            }
            catch (AuthenticationTagMismatchException)
            {
                // Sai tag LÚC BẮT TAY = hai bên không cùng khóa (vd. MITM thay khóa tạm) → xác thực thất bại
                reason = c.Info is null ? CloseReason.AuthFailed : CloseReason.Tampered;
            }
            catch (CryptographicException) { reason = c.Info is null ? CloseReason.AuthFailed : CloseReason.Tampered; }
            catch (SelfConnectionException) { reason = CloseReason.SelfConnection; }
            catch (HlcProtocolException) { reason = CloseReason.ProtocolError; }
            catch (JsonException) { reason = CloseReason.ProtocolError; }
            catch (EndOfStreamException) { reason = c.Draining ? CloseReason.PeerLeft : CloseReason.Closed; }
            catch (OperationCanceledException)
            {
                reason = c.IsClosed ? c.Reason : (c.Info is null ? CloseReason.Timeout : CloseReason.Closed);
            }
            catch (Exception ex) { reason = ClassifyIo(ex); }
            finally
            {
                Close(c, reason);
                c.Rx?.Dispose();
            }
        }

        private sealed class SelfConnectionException : Exception { }

        private void ProcessHello(Connection c, byte[] helloBytes)
        {
            var h = JsonSerializer.Deserialize<HelloMsg>(helloBytes)
                    ?? throw new HlcProtocolException("Hello rỗng");
            if (h.P != Protocol.Magic || h.V != Protocol.Version)
                throw new HlcProtocolException($"Sai phiên bản giao thức ({h.P} v{h.V})");
            if (h.Id is null || h.Eph is null || h.Nonce is null || h.Nonce.Length != Handshake.NonceSize ||
                h.Id.Length > 512 || h.Eph.Length > 512 || h.Port is <= 0 or > 65535)
                throw new HlcProtocolException("Hello thiếu trường");
            if (!CryptoService.IsValidIdentityKey(h.Id))
                throw new CryptographicException("Khóa danh tính không hợp lệ");

            string fp = CryptoService.ComputeFingerprint(h.Id);
            if (fp == _crypto.Fingerprint) throw new SelfConnectionException();

            byte[] theirHello = helloBytes;
            var keys = c.IsInitiator
                ? Handshake.Derive(c.Ephemeral, h.Eph, c.MyHello, theirHello)
                : Handshake.Derive(c.Ephemeral, h.Eph, theirHello, c.MyHello);
            c.Ephemeral.Dispose(); // hủy khóa tạm NGAY → forward secrecy

            c.Tx = new CipherState(c.IsInitiator ? keys.InitiatorToResponder : keys.ResponderToInitiator);
            c.Rx = new CipherState(c.IsInitiator ? keys.ResponderToInitiator : keys.InitiatorToResponder);
            c.Transcript = keys.Transcript;
            c.PeerHello = h with { Name = Clean(h.Name) };
            c.Fingerprint = fp;

            if (TraceEnabled)
            {
                Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), false, "Hello", null,
                    Protocol.HeaderSize + helloBytes.Length, null,
                    Convert.ToHexString(helloBytes, 0, Math.Min(16, helloBytes.Length)),
                    $"Peer Hello · Id={fp} · Eph=P-256 · v{h.V} · port {h.Port} · PLAINTEXT"));
                Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), false, "KEY", null, 0, null,
                    Convert.ToHexString(keys.Transcript, 0, 8),
                    $"ECDHE(P-256) → Z · HKDF-SHA256(salt = SHA-256(transcript)) → k_i2r, k_r2i (AES-256-GCM) · " +
                    $"role {(c.IsInitiator ? "initiator" : "responder")} · ephemeral private key DESTROYED (PFS)"));
            }

            // Auth phải là gói Sealed ĐẦU TIÊN → enqueue trước khi mở cổng cho writer
            byte[] sig = _crypto.Sign(Handshake.AuthData(keys.Transcript, c.IsInitiator));
            TryEnqueueHigh(c, new OutFrame(PacketType.Auth, sig, 0, sig.Length, false, null), allowBeforeAuth: true);
            c.KeysReady.TrySetResult();

            static string Clean(string? s)
            {
                s = new string((s ?? "").Where(ch => !char.IsControl(ch)).Take(64).ToArray()).Trim();
                return s.Length == 0 ? "(unnamed)" : s;
            }
        }

        private static void VerifyAuth(Connection c, ReadOnlySpan<byte> signature)
        {
            byte[] expected = Handshake.AuthData(c.Transcript!, asInitiator: !c.IsInitiator);
            if (!CryptoService.Verify(c.PeerHello!.Id, expected, signature))
                throw new CryptographicException("Chữ ký Auth sai — có thể bị tấn công MITM");
        }

        private void OnAuthenticated(Connection c)
        {
            var h = c.PeerHello!;
            var info = new PeerSessionInfo(c.Fingerprint!, h.Name, h.Id, c.Remote, h.Port,
                                           ComposeSessionId(c), c.IsInitiator, h.Instance);
            c.Info = info;
            c.LastRxTick = Environment.TickCount64;

            Connection? loser = null;
            bool becameActive;
            lock (_sessionLock)
            {
                if (_sessions.TryGetValue(info.Fingerprint, out var existing) && existing != c && !existing.IsClosed)
                {
                    if (PreferNew(existing, c)) { _sessions[info.Fingerprint] = c; loser = existing; becameActive = true; }
                    else { loser = c; becameActive = false; }
                }
                else
                {
                    _sessions[info.Fingerprint] = c;
                    becameActive = true;
                }
            }

            AddEndpoint(info.Fingerprint, info.ListenEndPoint);
            c.Authenticated.TrySetResult(info);
            if (loser is not null) BeginGracefulClose(loser, CloseReason.Replaced);
            if (becameActive) Raise(() => SessionEstablished?.Invoke(info));
        }

        private static string ComposeSessionId(Connection c)
        {
            // Session ID dẫn xuất từ transcript — hai bên hiển thị giống hệt nhau
            byte[] h = SHA256.HashData(c.Transcript!);
            return Convert.ToHexString(h, 0, 6);
        }

        /// <summary>
        /// Tie-break TẤT ĐỊNH khi có 2 kết nối cùng tới một peer (cả hai bấm gửi cùng lúc):
        /// giữ kết nối do bên có fingerprint NHỎ HƠN khởi tạo. Hai bên tự tính ra cùng một
        /// kết luận mà không cần trao đổi gì thêm. Cùng người khởi tạo → giữ kết nối mới hơn
        /// (trường hợp reconnect sau khi mạng chập chờn).
        /// </summary>
        private bool PreferNew(Connection existing, Connection candidate)
        {
            string InitiatorOf(Connection x) => x.IsInitiator ? _crypto.Fingerprint : x.Fingerprint!;
            string a = InitiatorOf(existing), b = InitiatorOf(candidate);
            if (a == b) return true;
            return string.CompareOrdinal(b, a) < 0;
        }

        private ValueTask DispatchAsync(Connection c, PacketType type, ReadOnlyMemory<byte> payload)
        {
            string fp = c.Fingerprint!;
            switch (type)
            {
                case PacketType.Ping:
                    // KHÔNG await ghi trong reader loop (tránh deadlock khi 2 bên cùng đẩy file)
                    TryEnqueueHigh(c, new OutFrame(PacketType.Pong, payload.ToArray(), 0, payload.Length, false, null));
                    return ValueTask.CompletedTask;

                case PacketType.Pong:
                    if (payload.Length == 8)
                    {
                        long sent = BinaryPrimitives.ReadInt64LittleEndian(payload.Span);
                        int rtt = (int)Math.Clamp(Environment.TickCount64 - sent, 0, 60_000);
                        c.RttMs = rtt;
                        if (GetActive(fp) == c) Raise(() => RttUpdated?.Invoke(fp, rtt));
                    }
                    return ValueTask.CompletedTask;

                case PacketType.Bye:
                    // Bên kia đóng êm (thoát app / tie-break). Ngừng dùng kết nối này để gửi.
                    BeginGracefulClose(c, CloseReason.PeerLeft);
                    return ValueTask.CompletedTask;

                case PacketType.Auth:
                    throw new HlcProtocolException("Auth lặp lại");

                case PacketType.Text:
                    string text = Encoding.UTF8.GetString(payload.Span);
                    Raise(() => TextReceived?.Invoke(fp, text));
                    return ValueTask.CompletedTask;

                default:
                    return InvokeFrameHandlerAsync(fp, type, payload);
            }
        }

        private async ValueTask InvokeFrameHandlerAsync(string fp, PacketType type, ReadOnlyMemory<byte> payload)
        {
            if (!_handlers.TryGetValue(type, out var handler)) return; // loại gói chưa ai đăng ký → bỏ qua
            try { await handler(fp, type, payload).ConfigureAwait(false); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // Lỗi tầng ứng dụng không được phép giết kết nối của mọi transfer khác
                System.Diagnostics.Debug.WriteLine($"[FrameHandler] {type}: {ex}");
            }
        }

        // ---------------- Heartbeat ----------------

        private async Task HeartbeatLoopAsync(Connection c)
        {
            CancellationToken ct = c.Cts.Token;
            try
            {
                await c.Authenticated.Task.WaitAsync(ct).ConfigureAwait(false);
                byte[] ping = new byte[8];
                while (!ct.IsCancellationRequested)
                {
                    BinaryPrimitives.WriteInt64LittleEndian(ping, Environment.TickCount64);
                    TryEnqueueHigh(c, new OutFrame(PacketType.Ping, (byte[])ping.Clone(), 0, 8, false, null));
                    await Task.Delay(PingIntervalMs, ct).ConfigureAwait(false);

                    if (Environment.TickCount64 - Volatile.Read(ref c.LastRxTick) > DeadAfterMs)
                    {
                        Close(c, CloseReason.Timeout); // im lặng quá lâu → coi như mất mạng
                        return;
                    }
                }
            }
            catch { /* kết nối đã đóng */ }
        }

        // ---------------- Đóng kết nối ----------------

        /// <summary>Đóng êm: gửi nốt hàng đợi → Bye → FIN; reader nhận nốt dữ liệu của bên kia.</summary>
        private void BeginGracefulClose(Connection c, CloseReason reason)
        {
            if (c.IsClosed || c.Draining) return;
            c.Reason = reason;
            c.Draining = true;
            DetachSession(c, reason);
            c.Items.Release(); // đánh thức writer
            _ = Task.Delay(4000).ContinueWith(_ => Close(c, reason), TaskScheduler.Default);
        }

        private void Close(Connection c, CloseReason reason)
        {
            if (Interlocked.Exchange(ref c.ClosedFlag, 1) == 1) return;
            if (!c.Draining) c.Reason = reason;
            try { c.Cts.Cancel(); } catch { }
            try { c.Client.Dispose(); } catch { }
            try { c.Ephemeral.Dispose(); } catch { }
            DrainQueues(c);
            _all.TryRemove(c.Id, out _);
            DetachSession(c, c.Reason);

            if (TraceEnabled)
                Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), false, "CLOSE", null, 0, null, "",
                    $"Connection closed: {c.Reason}"));

            if (!c.Authenticated.Task.IsCompleted)
            {
                c.Authenticated.TrySetException(new PeerUnavailableException(DescribeReject(c.Reason), c.Reason));
                if (c.Reason is CloseReason.Tampered or CloseReason.AuthFailed or CloseReason.ProtocolError
                             or CloseReason.SelfConnection or CloseReason.Timeout)
                {
                    Interlocked.Increment(ref _rejected);
                    Raise(() => ConnectionRejected?.Invoke(c.Remote.ToString(), c.Reason, DescribeReject(c.Reason)));
                }
            }
            else if (c.Reason == CloseReason.Tampered)
            {
                Interlocked.Increment(ref _rejected);
            }
        }

        private long _rejected;
        /// <summary>Số kết nối/phiên bị cắt vì lý do an ninh (giả mạo, sai chữ ký, sai giao thức...).</summary>
        public long RejectedConnections => Interlocked.Read(ref _rejected);

        // ---------------- Protocol Inspector ----------------

        private static string PeerLabel(Connection c) => c.Info?.Name ?? c.PeerHello?.Name ?? c.Remote.ToString();

        private void Emit(FrameTrace t)
        {
            try { FrameTraced?.Invoke(t); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Trace] {ex.Message}"); }
        }

        /// <summary>Ghi lại một record Sealed. Record dữ liệu khối được GỘP (tối đa ~4 dòng/giây/chiều).</summary>
        private void TraceSealed(Connection c, bool outgoing, PacketType inner, int wire, ulong seq,
                                 ReadOnlySpan<byte> cipherPreview, int plainLen,
                                 ref int agg, ref long aggBytes, ref long aggTick)
        {
            if (inner is PacketType.FileChunk or PacketType.LinkProbe)
            {
                agg++;
                aggBytes += wire;
                long now = Environment.TickCount64;
                if (now - aggTick < 250) return;
                aggTick = now;
                int n = agg; long b = aggBytes;
                agg = 0; aggBytes = 0;
                Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), outgoing, "Sealed", inner, (int)Math.Min(b, int.MaxValue),
                    seq, Convert.ToHexString(cipherPreview), $"{n} bulk records · {b / 1024} KB · seq up to {seq}", n));
                return;
            }
            string note = inner switch
            {
                PacketType.Ping => "heartbeat ping (RTT probe)",
                PacketType.Pong => "heartbeat pong",
                PacketType.Auth => "ECDSA signature over handshake transcript",
                PacketType.Text => $"chat message · {plainLen} B plaintext",
                PacketType.Bye => "graceful close",
                _ => $"{plainLen} B plaintext",
            };
            Emit(new FrameTrace(DateTime.Now, c.Id, PeerLabel(c), outgoing, "Sealed", inner, wire, seq,
                Convert.ToHexString(cipherPreview), note));
        }

        private void DetachSession(Connection c, CloseReason reason)
        {
            if (c.Fingerprint is null) return;
            bool lost = false;
            lock (_sessionLock)
            {
                if (_sessions.TryGetValue(c.Fingerprint, out var cur) && cur == c)
                {
                    _sessions.Remove(c.Fingerprint);
                    lost = true;
                }
            }
            if (lost && reason != CloseReason.Replaced)
            {
                string fp = c.Fingerprint;
                Raise(() => SessionLost?.Invoke(fp, reason));
            }
        }

        private static string DescribeReject(CloseReason r) => r switch
        {
            CloseReason.SelfConnection => "Đây là chính máy này",
            CloseReason.AuthFailed => "Xác thực danh tính thất bại",
            CloseReason.Tampered => "Gói bị sửa đổi trên đường truyền",
            CloseReason.ProtocolError => "Sai giao thức",
            CloseReason.Timeout => "Hết thời gian bắt tay",
            _ => "Kết nối bị đóng",
        };

        private static CloseReason ClassifyIo(Exception ex) => ex switch
        {
            AuthenticationTagMismatchException => CloseReason.Tampered,
            HlcProtocolException => CloseReason.ProtocolError,
            EndOfStreamException => CloseReason.Closed,
            _ => CloseReason.NetworkError,
        };

        private static void Raise(Action a)
        {
            try { a(); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[Messaging event] {ex}"); }
        }

        /// <summary>CHỈ DÙNG CHO TEST: cắt phăng mọi kết nối (giả lập rút dây mạng).</summary>
        internal void DebugKillConnections()
        {
            foreach (var c in _all.Values) Close(c, CloseReason.NetworkError);
        }

        public void Dispose()
        {
            if (_cts.IsCancellationRequested) return;
            // Báo Bye cho mọi peer để họ thấy mình offline NGAY (không phải chờ timeout 12s)
            var writers = new List<Task>();
            foreach (var c in _all.Values)
            {
                if (c.Authenticated.Task.IsCompletedSuccessfully)
                {
                    BeginGracefulClose(c, CloseReason.Shutdown);
                    if (c.WriterTask is not null) writers.Add(c.WriterTask);
                }
            }
            try { Task.WhenAll(writers).Wait(TimeSpan.FromMilliseconds(400)); } catch { }

            _cts.Cancel();
            try { _listener?.Stop(); } catch { }
            foreach (var c in _all.Values) Close(c, CloseReason.Shutdown);
        }
    }
}
