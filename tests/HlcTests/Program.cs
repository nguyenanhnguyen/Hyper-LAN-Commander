// =============================================================================
//  Hyper-LAN Commander — integration test runner (real sockets, real crypto)
//
//    dotnet run --project tests/HlcTests                 # protocol / transfer suite
//    dotnet run --project tests/HlcTests -- resume       # only tests whose name contains "resume"
//    dotnet run --project tests/HlcTests -- security     # Attack Lab + host audit + ARP + link test
//
//  Every node binds to 127.0.0.1 on an ephemeral port and uses a throw-away identity
//  under %TEMP%, which is deleted at the end. Nothing is exposed to the network.
// =============================================================================
using System.IO;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using networkApp;

if (args.Contains("security")) return await SecurityTests.RunAsync();
bool only(string n) => args.Length == 0 || args.Any(a => n.Contains(a, StringComparison.OrdinalIgnoreCase));
string root = Path.Combine(Path.GetTempPath(), "hlc-tests-" + Environment.ProcessId);
Directory.CreateDirectory(root);
int failures = 0;

async Task Run(string name, Func<Task> body, int timeoutSec = 90)
{
    if (!only(name)) return;
    var sw = Stopwatch.StartNew();
    try
    {
        var t = body();
        if (await Task.WhenAny(t, Task.Delay(TimeSpan.FromSeconds(timeoutSec))) != t)
            throw new TimeoutException($"test timed out after {timeoutSec}s");
        await t;
        Console.WriteLine($"PASS  {name}  ({sw.ElapsedMilliseconds} ms)");
    }
    catch (Exception ex)
    {
        failures++;
        Console.WriteLine($"FAIL  {name}: {ex}");
    }
}

void Assert(bool cond, string msg) { if (!cond) throw new Exception("Assert: " + msg); }

Node MakeNode(string name) => new(Path.Combine(root, name), name);

string MakeFile(string name, long size)
{
    string p = Path.Combine(root, name);
    using var fs = File.Create(p);
    var buf = new byte[1 << 20];
    long left = size;
    while (left > 0)
    {
        RandomNumberGenerator.Fill(buf);
        int n = (int)Math.Min(buf.Length, left);
        fs.Write(buf, 0, n);
        left -= n;
    }
    return p;
}

string Sha(string path) { using var f = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(f)); }

// ---------------------------------------------------------------------------
await Run("Identity: legacy v1 ECDH key migrates with SAME fingerprint, DPAPI reload stable", async () =>
{
    string dir = Path.Combine(root, "legacy");
    Directory.CreateDirectory(dir);
    using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    File.WriteAllBytes(Path.Combine(dir, "identity.key"), ecdh.ExportPkcs8PrivateKey());
    string expected = CryptoService.ComputeFingerprint(ecdh.ExportSubjectPublicKeyInfo());

    using var c1 = new CryptoService(dir);
    Assert(c1.Fingerprint == expected, $"fp {c1.Fingerprint} != {expected}");
    byte[] raw = File.ReadAllBytes(Path.Combine(dir, "identity.key"));
    Assert(raw.AsSpan().StartsWith("HLCK2"u8), "file not upgraded to DPAPI format");
    using var c2 = new CryptoService(dir);
    Assert(c2.Fingerprint == expected, "fingerprint changed after reload");
    byte[] data = "hello"u8.ToArray();
    Assert(CryptoService.Verify(c2.PublicKey, data, c1.Sign(data)), "signature does not verify");
    await Task.CompletedTask;
});

await Run("Safety number is symmetric and differs per pair", async () =>
{
    using var a = new CryptoService(Path.Combine(root, "sa"));
    using var b = new CryptoService(Path.Combine(root, "sb"));
    using var c = new CryptoService(Path.Combine(root, "sc"));
    string ab = CryptoService.SafetyNumber(a.PublicKey, b.PublicKey);
    Assert(ab == CryptoService.SafetyNumber(b.PublicKey, a.PublicKey), "not symmetric");
    Assert(ab != CryptoService.SafetyNumber(a.PublicKey, c.PublicKey), "collision");
    Console.WriteLine("      safety: " + ab.Replace("\n", " | "));
    await Task.CompletedTask;
});

await Run("Sanitize hostile file names", async () =>
{
    Assert(FileTransferService.SanitizeFileName(@"..\..\Windows\evil.exe") == "evil.exe", "traversal \\");
    Assert(FileTransferService.SanitizeFileName("../../etc/passwd") == "passwd", "traversal /");
    Assert(FileTransferService.SanitizeFileName("CON.txt") == "_CON.txt", "dos device");
    Assert(FileTransferService.SanitizeFileName("a<b>c?.txt") == "a_b_c_.txt", "invalid chars");
    Assert(FileTransferService.SanitizeFileName("   ") == "unnamed", "empty");
    await Task.CompletedTask;
});

// ---------------------------------------------------------------------------
await Run("Handshake + bidirectional encrypted chat + RTT", async () =>
{
    using var a = MakeNode("A1"); using var b = MakeNode("B1");
    a.Know(b);
    await a.Msg.SendTextAsync(b.Fp, "xin chào 👋");
    var (from, text) = await b.NextText();
    Assert(from == a.Fp && text == "xin chào 👋", "wrong text/sender");
    await b.Msg.SendTextAsync(a.Fp, "pong"); // B chưa có endpoint — phải dùng lại phiên đang có
    Assert((await a.NextText()).Text == "pong", "reply");
    Assert(a.Msg.SessionCount == 1 && b.Msg.SessionCount == 1, "session count");
    var sa = a.Msg.GetSession(b.Fp)!; var sb = b.Msg.GetSession(a.Fp)!;
    Assert(sa.SessionId == sb.SessionId, "session id must match on both sides");
    int rtt = await a.WaitRtt(b.Fp);
    Console.WriteLine($"      session {sa.SessionId}, RTT {rtt} ms");
});

await Run("Simultaneous connect from both sides converges to ONE session, no message lost", async () =>
{
    using var a = MakeNode("A2"); using var b = MakeNode("B2");
    a.Know(b); b.Know(a);
    var sends = new List<Task>();
    for (int i = 0; i < 20; i++)
    {
        sends.Add(a.Msg.SendTextAsync(b.Fp, "a" + i));
        sends.Add(b.Msg.SendTextAsync(a.Fp, "b" + i));
    }
    await Task.WhenAll(sends);
    var gotA = new HashSet<string>(); var gotB = new HashSet<string>();
    for (int i = 0; i < 20; i++) { gotB.Add((await b.NextText()).Text); gotA.Add((await a.NextText()).Text); }
    Assert(gotA.Count == 20 && gotB.Count == 20, "missing messages");
    await Task.Delay(1500);
    Assert(a.Msg.SessionCount == 1 && b.Msg.SessionCount == 1, $"sessions {a.Msg.SessionCount}/{b.Msg.SessionCount}");
    Assert(a.Msg.GetSession(b.Fp)!.SessionId == b.Msg.GetSession(a.Fp)!.SessionId, "both sides must keep the SAME connection");
});

await Run("Self-connection is detected", async () =>
{
    using var a = MakeNode("A3");
    try { await a.Msg.ConnectAsync("127.0.0.1", a.Port); throw new Exception("should have failed"); }
    catch (PeerUnavailableException ex) { Assert(ex.Reason == CloseReason.SelfConnection, "reason " + ex.Reason); }
});

await Run("Garbage / silent clients are dropped, service stays healthy", async () =>
{
    using var a = MakeNode("A4"); using var b = MakeNode("B4");
    using (var junk = new TcpClient())
    {
        await junk.ConnectAsync(IPAddress.Loopback, a.Port);
        await junk.GetStream().WriteAsync(new byte[] { 0x01, 0xFF, 0xFF, 0xFF, 0x7F, 1, 2, 3 });
        var buf = new byte[4096];
        var s = junk.GetStream();
        try { int n; do { n = await s.ReadAsync(buf).AsTask().WaitAsync(TimeSpan.FromSeconds(5)); } while (n > 0); } // Hello rồi EOF
        catch (IOException) { /* RST: server đóng khi còn dữ liệu chưa đọc — cũng là bị đá */ }
    }
    using var silent = new TcpClient();
    await silent.ConnectAsync(IPAddress.Loopback, a.Port);
    b.Know(a);
    await b.Msg.SendTextAsync(a.Fp, "still alive?");
    Assert((await a.NextText()).Text == "still alive?", "service broken");
    var sw = Stopwatch.StartNew();
    var sbuf = new byte[4096];
    int r; do { r = await silent.GetStream().ReadAsync(sbuf).AsTask().WaitAsync(TimeSpan.FromSeconds(10)); } while (r > 0);
    Console.WriteLine($"      silent client dropped after {sw.ElapsedMilliseconds} ms (handshake deadline)");
});

// ---------------------------------------------------------------------------
await Run("File 96 MB: consent → transfer → SHA-256 verified on both ends", async () =>
{
    using var a = MakeNode("A5"); using var b = MakeNode("B5");
    a.Know(b);
    b.AutoAccept = true;
    string src = MakeFile("big.bin", 96L << 20);
    var sw = Stopwatch.StartNew();
    Guid id = a.Files.StartSend(b.Fp, src);
    var sendDone = await a.WaitFinal(id);
    var recvDone = await b.WaitFinal(id);
    Assert(sendDone.State == TransferState.Completed, "sender " + sendDone.State + " " + sendDone.Detail);
    Assert(recvDone.State == TransferState.Completed, "receiver " + recvDone.State);
    Assert(Sha(recvDone.LocalPath!) == Sha(src), "content differs");
    Assert(sendDone.Detail == recvDone.Detail, "hash reported differs");
    Console.WriteLine($"      {96.0 / sw.Elapsed.TotalSeconds:0} MB/s over loopback (AES-256-GCM + SHA-256 + disk)");
});

await Run("Chat stays responsive during a bulk transfer (priority queues)", async () =>
{
    using var a = MakeNode("A6"); using var b = MakeNode("B6");
    a.Know(b); b.AutoAccept = true;
    string src = MakeFile("prio.bin", 160L << 20);
    Guid id = a.Files.StartSend(b.Fp, src);
    await b.WaitState(id, TransferState.Transferring);
    await Task.Delay(300);
    var lat = new List<long>();
    for (int i = 0; i < 5; i++)
    {
        var sw = Stopwatch.StartNew();
        await a.Msg.SendTextAsync(b.Fp, "ping" + i);
        await b.NextText();
        lat.Add(sw.ElapsedMilliseconds);
    }
    var done = await b.WaitFinal(id);
    Assert(done.State == TransferState.Completed, "transfer " + done.State);
    Console.WriteLine($"      chat latency during transfer: {string.Join(", ", lat)} ms");
    Assert(lat.Max() < 1000, "chat starved by bulk transfer");
});

await Run("Connection killed mid-transfer → sender reconnects and RESUMES automatically", async () =>
{
    using var a = MakeNode("A7"); using var b = MakeNode("B7");
    a.Know(b); b.AutoAccept = true;
    string src = MakeFile("resume.bin", 200L << 20);
    Guid id = a.Files.StartSend(b.Fp, src);
    await b.WaitProgress(id, 0.3);
    a.Msg.DebugKillConnections(); // giả lập rớt mạng (RST)
    b.Msg.DebugKillConnections();
    var r = await b.WaitFinal(id, 120);
    var s = await a.WaitFinal(id, 30);
    Assert(r.State == TransferState.Completed && s.State == TransferState.Completed, $"states {s.State}/{r.State} {s.Detail}");
    Assert(s.Reconnects + r.Reconnects >= 1, "no reconnect happened?");
    Assert(Sha(r.LocalPath!) == Sha(src), "content differs after resume");
    Assert(b.Seen(id).Any(x => x.State == TransferState.Paused) || a.Seen(id).Any(x => x.State == TransferState.Reconnecting),
           "never saw paused/reconnecting");
    Console.WriteLine($"      reconnects sender={s.Reconnects} receiver={r.Reconnects}; receiver states: " +
                      string.Join(" > ", b.Seen(id).Select(x => x.State).Where((x, i) => i == 0 || b.Seen(id).ElementAt(i - 1).State != x)));
});

await Run("Receiver-side drop only (sender unaware) → resync, completes quickly", async () =>
{
    using var a = MakeNode("A7b"); using var b = MakeNode("B7b");
    a.Know(b); b.AutoAccept = true;
    string src = MakeFile("resume2.bin", 160L << 20);
    Guid id = a.Files.StartSend(b.Fp, src);
    await b.WaitProgress(id, 0.25);
    var sw = Stopwatch.StartNew();
    b.Msg.DebugKillConnections();
    await Task.Delay(200);
    await b.WaitProgress(id, 0.6);
    b.Msg.DebugKillConnections(); // rớt lần 2
    var r = await b.WaitFinal(id, 60);
    Assert(r.State == TransferState.Completed, "state " + r.State);
    Assert(Sha(r.LocalPath!) == Sha(src), "content differs");
    Console.WriteLine($"      2 drops, finished {sw.ElapsedMilliseconds} ms after first drop");
    Assert(sw.ElapsedSeconds() < 20, "too slow to recover");
});

await Run("Partial file of a DIFFERENT version is not appended (content-keyed .part)", async () =>
{
    using var a = MakeNode("A8"); using var b = MakeNode("B8");
    a.Know(b); b.AutoAccept = true;
    string src = MakeFile("ver.bin", 256L << 20);
    Guid id1 = a.Files.StartSend(b.Fp, src);
    await b.WaitProgress(id1, 0.15);
    b.Files.Cancel(id1);
    await a.WaitFinal(id1);
    // sửa nội dung, giữ nguyên tên + kích thước
    await Task.Delay(50);
    using (var fs = new FileStream(src, FileMode.Open)) { fs.Position = 10; fs.Write(new byte[] { 1, 2, 3, 4, 5 }); }
    File.SetLastWriteTimeUtc(src, DateTime.UtcNow.AddMinutes(1));
    Guid id2 = a.Files.StartSend(b.Fp, src);
    var r = await b.WaitFinal(id2);
    Assert(r.State == TransferState.Completed, "state " + r.State);
    Assert(r.ResumedFrom == 0, "must NOT resume from a different version, resumed from " + r.ResumedFrom);
    Assert(Sha(r.LocalPath!) == Sha(src), "content differs");
});

await Run("Cancel then resend same file → resumes from the partial data", async () =>
{
    using var a = MakeNode("A9"); using var b = MakeNode("B9");
    a.Know(b); b.AutoAccept = true;
    string src = MakeFile("again.bin", 256L << 20);
    Guid id1 = a.Files.StartSend(b.Fp, src);
    await b.WaitProgress(id1, 0.2);
    a.Files.Cancel(id1);
    var c = await b.WaitFinal(id1);
    Assert(c.State == TransferState.Canceled, "receiver should see cancel, got " + c.State);
    Guid id2 = a.Files.StartSend(b.Fp, src);
    var r = await b.WaitFinal(id2);
    Assert(r.State == TransferState.Completed, "state " + r.State);
    Assert(r.ResumedFrom > 0, "expected resume");
    Assert(Sha(r.LocalPath!) == Sha(src), "content differs");
    Console.WriteLine($"      resumed from {r.ResumedFrom * 100 / r.Size}%");
});

await Run("Decline → sender sees Rejected; nobody writes data", async () =>
{
    using var a = MakeNode("A10"); using var b = MakeNode("B10");
    a.Know(b); b.AutoReject = true;
    string src = MakeFile("no.bin", 1 << 20);
    Guid id = a.Files.StartSend(b.Fp, src);
    var s = await a.WaitFinal(id);
    Assert(s.State == TransferState.Rejected, "state " + s.State);
    Assert(!Directory.EnumerateFiles(b.Files.SaveFolder, "no.bin*").Any(), "data landed on disk without consent");
});

await Run("Tampering proxy flips ONE byte → fail-closed, then direct reconnect completes the transfer", async () =>
{
    using var a = MakeNode("A11"); using var b = MakeNode("B11");
    using var proxy = new TamperProxy(b.Port, flipAfterBytes: 3_000_000);
    a.Msg.AddEndpoint(b.Fp, new IPEndPoint(IPAddress.Loopback, proxy.Port));
    b.AutoAccept = true;
    var lost = new ConcurrentQueue<CloseReason>();
    b.Msg.SessionLost += (_, r) => lost.Enqueue(r);
    string src = MakeFile("tamper.bin", 32L << 20);
    Guid id = a.Files.StartSend(b.Fp, src);
    var r = await b.WaitFinal(id, 90);
    Assert(lost.Contains(CloseReason.Tampered), "tampering not detected: " + string.Join(",", lost));
    Assert(r.State == TransferState.Completed, "state " + r.State);
    Assert(Sha(r.LocalPath!) == Sha(src), "corrupted content accepted!");
    Console.WriteLine($"      proxy flipped a byte at offset {proxy.FlippedAt}; receiver closed: {string.Join(",", lost)}");
});

await Run("Graceful shutdown → peer sees PeerLeft immediately (Bye), not after timeout", async () =>
{
    using var a = MakeNode("A12"); var b = MakeNode("B12");
    a.Know(b);
    await a.Msg.SendTextAsync(b.Fp, "hi");
    await b.NextText();
    var tcs = new TaskCompletionSource<CloseReason>();
    a.Msg.SessionLost += (_, r) => tcs.TrySetResult(r);
    var sw = Stopwatch.StartNew();
    b.Dispose();
    var reason = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(5));
    Console.WriteLine($"      lost after {sw.ElapsedMilliseconds} ms, reason {reason}");
    Assert(reason == CloseReason.PeerLeft, "reason " + reason);
});

// ---------------------------------------------------------------------------
await Run("Discovery: two instances on one machine find each other (announce/reply, multi-NIC)", async () =>
{
    var ifs = DiscoveryService.EnumerateInterfaces();
    Console.WriteLine("      interfaces: " + (ifs.Count == 0 ? "(none)" : string.Join(" | ", ifs)));
    using var d1 = new DiscoveryService(Guid.NewGuid(), "AAAA-0000-0000-0001", "disc-1", 40001);
    using var d2 = new DiscoveryService(Guid.NewGuid(), "AAAA-0000-0000-0002", "disc-2", 40002);
    var seen1 = new TaskCompletionSource<DiscoveredPeer>(); var seen2 = new TaskCompletionSource<DiscoveredPeer>();
    d1.PeerSeen += p => { if (p.Fingerprint.EndsWith("2")) seen1.TrySetResult(p); };
    d2.PeerSeen += p => { if (p.Fingerprint.EndsWith("1")) seen2.TrySetResult(p); };
    var lost = new TaskCompletionSource<DiscoveredPeer>();
    d1.PeerLost += p => lost.TrySetResult(p);
    var sw = Stopwatch.StartNew();
    d1.Start(); d2.Start();
    var p1 = await seen1.Task.WaitAsync(TimeSpan.FromSeconds(8));
    var p2 = await seen2.Task.WaitAsync(TimeSpan.FromSeconds(8));
    Console.WriteLine($"      mutual discovery in {sw.ElapsedMilliseconds} ms: {p1.TcpEndPoint} / {p2.TcpEndPoint}, shared port={d1.ListeningOnSharedPort}");
    Assert(p1.TcpEndPoint.Port == 40002 && p2.TcpEndPoint.Port == 40001, "tcp port not carried");
    sw.Restart();
    d2.Dispose(); // Bye
    await lost.Task.WaitAsync(TimeSpan.FromSeconds(5));
    Console.WriteLine($"      Bye → PeerLost in {sw.ElapsedMilliseconds} ms");
});

Console.WriteLine(failures == 0 ? "\nALL TESTS PASSED" : $"\n{failures} TEST(S) FAILED");
try { Directory.Delete(root, true); } catch { }
return failures == 0 ? 0 : 1;

// ===========================================================================
static class SwExt { public static double ElapsedSeconds(this Stopwatch s) => s.Elapsed.TotalSeconds; }

sealed class Node : IDisposable
{
    public CryptoService Crypto { get; }
    public MessagingService Msg { get; }
    public FileTransferService Files { get; }
    public string Fp => Crypto.Fingerprint;
    public int Port => Msg.ListenPort;
    public BlockingCollection<(string From, string Text)> Texts { get; } = new();
    public Task<(string From, string Text)> NextText() => Task.Run(() => Texts.TryTake(out var v, 10000) ? v : throw new TimeoutException("no text"));
    public bool AutoAccept, AutoReject;
    private readonly ConcurrentDictionary<Guid, ConcurrentQueue<TransferSnapshot>> _snaps = new();
    private readonly ConcurrentDictionary<string, int> _rtt = new();
    private bool _disposed;

    public Node(string dir, string name)
    {
        Crypto = new CryptoService(Path.Combine(dir, "data"));
        Msg = new MessagingService(Crypto, name, preferredPort: 0, bindAddress: IPAddress.Loopback);
        Files = new FileTransferService(Msg, Path.Combine(dir, "dl"));
        Msg.TextReceived += (f, t) => Texts.Add((f, t));
        Msg.RttUpdated += (f, ms) => _rtt[f] = ms;
        Files.Updated += s =>
        {
            _snaps.GetOrAdd(s.Id, _ => new()).Enqueue(s);
            if (s.State == TransferState.AwaitingDecision)
            {
                if (AutoAccept) _ = Files.AcceptAsync(s.Id);
                else if (AutoReject) _ = Files.RejectAsync(s.Id);
            }
        };
        Msg.Start();
    }

    public void Know(Node other) => Msg.AddEndpoint(other.Fp, new IPEndPoint(IPAddress.Loopback, other.Port));

    public IEnumerable<TransferSnapshot> Seen(Guid id) => _snaps.TryGetValue(id, out var q) ? q : Enumerable.Empty<TransferSnapshot>();

    public async Task<int> WaitRtt(string fp)
    {
        for (int i = 0; i < 100; i++) { if (_rtt.TryGetValue(fp, out int v)) return v; await Task.Delay(100); }
        throw new TimeoutException("no RTT");
    }

    public async Task<TransferSnapshot> WaitFinal(Guid id, int sec = 60)
    {
        var until = DateTime.UtcNow.AddSeconds(sec);
        while (DateTime.UtcNow < until)
        {
            var last = Seen(id).LastOrDefault();
            if (last is { State: TransferState.Completed or TransferState.Failed or TransferState.Rejected or TransferState.Canceled })
                return last;
            await Task.Delay(50);
        }
        throw new TimeoutException($"transfer {id} not final; last={Seen(id).LastOrDefault()?.State}");
    }

    public async Task WaitState(Guid id, TransferState st)
    {
        for (int i = 0; i < 600; i++) { if (Seen(id).Any(s => s.State == st)) return; await Task.Delay(50); }
        throw new TimeoutException("state " + st);
    }

    public async Task WaitProgress(Guid id, double fraction)
    {
        for (int i = 0; i < 1200; i++)
        {
            var l = Seen(id).LastOrDefault();
            if (l is not null && l.Size > 0 && l.Done >= l.Size * fraction && l.State == TransferState.Transferring) return;
            if (l is { State: TransferState.Completed or TransferState.Verifying }) return; // đã xong trước khi kịp thấy mốc
            await Task.Delay(20);
        }
        throw new TimeoutException("progress; last=" + string.Join(" > ", Seen(id).TakeLast(6).Select(x => $"{x.State}@{x.Done * 100 / Math.Max(1, x.Size)}%")));
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Files.Dispose(); Msg.Dispose(); Crypto.Dispose();
    }
}

/// <summary>MITM "chủ động": chuyển tiếp TCP nhưng lật 1 bit sau N byte theo chiều client→server.</summary>
sealed class TamperProxy : IDisposable
{
    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    private readonly int _target;
    private readonly long _flipAfter;
    private readonly CancellationTokenSource _cts = new();
    private int _flipped;
    public int Port { get; }
    public long FlippedAt { get; private set; } = -1;

    public TamperProxy(int target, long flipAfterBytes)
    {
        _target = target; _flipAfter = flipAfterBytes;
        _l.Start(); Port = ((IPEndPoint)_l.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient c;
                try { c = await _l.AcceptTcpClientAsync(_cts.Token); } catch { return; }
                var s = new TcpClient();
                await s.ConnectAsync(IPAddress.Loopback, _target);
                _ = Pump(c.GetStream(), s.GetStream(), tamper: true);
                _ = Pump(s.GetStream(), c.GetStream(), tamper: false);
            }
        });
    }

    private async Task Pump(NetworkStream from, NetworkStream to, bool tamper)
    {
        var buf = new byte[65536]; long total = 0;
        try
        {
            int n;
            while ((n = await from.ReadAsync(buf)) > 0)
            {
                if (tamper && total + n > _flipAfter && Interlocked.Exchange(ref _flipped, 1) == 0)
                {
                    int i = (int)Math.Max(0, _flipAfter - total);
                    buf[i] ^= 0x01;
                    FlippedAt = total + i;
                }
                total += n;
                await to.WriteAsync(buf.AsMemory(0, n));
            }
        }
        catch { }
        finally { from.Close(); to.Close(); }
    }

    public void Dispose() { _cts.Cancel(); _l.Stop(); }
}
