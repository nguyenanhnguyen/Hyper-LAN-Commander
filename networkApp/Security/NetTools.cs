using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp.Security
{
    /// <summary>Ping / traceroute / DNS — dùng ICMP của OS qua System.Net.NetworkInformation.Ping (không cần admin).</summary>
    public static class NetTools
    {
        public static async Task PingAsync(string host, int count, Action<string> output, CancellationToken ct)
        {
            IPAddress ip = await ResolveAsync(host, output).ConfigureAwait(false);
            output($"PING {host} [{ip}] — {count} × 32 B");
            var rtts = new List<long>();
            using var ping = new Ping();
            for (int i = 0; i < count && !ct.IsCancellationRequested; i++)
            {
                try
                {
                    var r = await ping.SendPingAsync(ip, 2000, new byte[32]).ConfigureAwait(false);
                    if (r.Status == IPStatus.Success)
                    {
                        rtts.Add(r.RoundtripTime);
                        output($"  reply from {r.Address}: time={r.RoundtripTime} ms ttl={r.Options?.Ttl}");
                    }
                    else output($"  {r.Status}");
                }
                catch (Exception ex) { output($"  error: {ex.Message}"); }
                await Task.Delay(500, ct).ConfigureAwait(false);
            }
            int lost = count - rtts.Count;
            output($"--- {count} sent, {rtts.Count} received, {lost * 100 / Math.Max(1, count)}% loss" +
                   (rtts.Count > 0 ? $", min/avg/max = {rtts.Min()}/{rtts.Average():0.0}/{rtts.Max()} ms, jitter {Jitter(rtts):0.0} ms" : ""));
        }

        /// <summary>
        /// Traceroute: gửi ICMP Echo với TTL = 1, 2, 3... Mỗi router trên đường đi giảm TTL, về 0 thì
        /// trả "TTL expired" kèm IP của nó → lộ ra từng chặng. (Cùng nguyên lý với tracert.exe.)
        /// </summary>
        public static async Task TracerouteAsync(string host, Action<string> output, CancellationToken ct)
        {
            IPAddress ip = await ResolveAsync(host, output).ConfigureAwait(false);
            output($"TRACEROUTE {host} [{ip}], max 20 hops");
            using var ping = new Ping();
            for (int ttl = 1; ttl <= 20 && !ct.IsCancellationRequested; ttl++)
            {
                var sw = Stopwatch.StartNew();
                PingReply? r = null;
                try { r = await ping.SendPingAsync(ip, 1500, new byte[32], new PingOptions(ttl, true)).ConfigureAwait(false); }
                catch { }
                long ms = sw.ElapsedMilliseconds;
                if (r is null || r.Status == IPStatus.TimedOut)
                {
                    output($"{ttl,3}   *        (no reply)");
                    continue;
                }
                string name = "";
                try
                {
                    var t = Dns.GetHostEntryAsync(r.Address);
                    if (await Task.WhenAny(t, Task.Delay(700, ct)).ConfigureAwait(false) == t && t.Result.HostName != r.Address.ToString())
                        name = "  " + t.Result.HostName;
                }
                catch { }
                output($"{ttl,3}  {ms,4} ms  {r.Address}{name}");
                if (r.Status == IPStatus.Success) { output("trace complete"); return; }
            }
        }

        public static async Task DnsLookupAsync(string host, Action<string> output)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                if (IPAddress.TryParse(host, out var ip))
                {
                    var e = await Dns.GetHostEntryAsync(ip).ConfigureAwait(false);
                    output($"PTR {ip} → {e.HostName}  ({sw.ElapsedMilliseconds} ms)");
                    return;
                }
                var addrs = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
                foreach (var a in addrs)
                    output($"{(a.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA" : "A   ")} {host} → {a}");
                output($"{addrs.Length} record(s) in {sw.ElapsedMilliseconds} ms");
                var servers = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == OperationalStatus.Up)
                    .SelectMany(n => n.GetIPProperties().DnsAddresses).Distinct().Select(a => a.ToString());
                output("resolvers: " + string.Join(", ", servers));
            }
            catch (Exception ex) { output($"lookup failed: {ex.Message}"); }
        }

        private static async Task<IPAddress> ResolveAsync(string host, Action<string> output)
        {
            if (IPAddress.TryParse(host, out var ip)) return ip;
            var addrs = await Dns.GetHostAddressesAsync(host).ConfigureAwait(false);
            return addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.First();
        }

        /// <summary>Jitter kiểu RFC 3550: trung bình độ lệch giữa các RTT liên tiếp.</summary>
        public static double Jitter(IReadOnlyList<long> rtts)
            => rtts.Count < 2 ? 0 : Enumerable.Range(1, rtts.Count - 1).Average(i => Math.Abs(rtts[i] - rtts[i - 1]));
    }

    public sealed record LinkTestResult(double RttMinMs, double RttAvgMs, double RttMaxMs, double JitterMs,
                                        int EchoLost, double ThroughputMBps, long Bytes, double Seconds);

    /// <summary>
    /// Đo đường truyền tới một peer QUA KÊNH MÃ HÓA THẬT (giống iperf + ping nhưng end-to-end):
    ///  • 20 gói LinkEcho (ưu tiên cao) → RTT min/avg/max, jitter, mất gói.
    ///  • 64 MB LinkProbe dữ liệu ngẫu nhiên (bulk) → bên nhận đếm byte & thời gian → thông lượng
    ///    thực tế SAU khi đã gồm chi phí AES-256-GCM, framing và TCP.
    /// </summary>
    public sealed class LinkTestService : IDisposable
    {
        private readonly MessagingService _msg;
        private readonly ConcurrentDictionary<long, TaskCompletionSource<long>> _echo = new();
        private readonly ConcurrentDictionary<Guid, (long Bytes, long StartTick)> _rx = new();
        private readonly ConcurrentDictionary<Guid, TaskCompletionSource<(long, long)>> _results = new();
        private long _echoSeq;

        public LinkTestService(MessagingService msg)
        {
            _msg = msg;
            _msg.RegisterHandler(HandleAsync, PacketType.LinkEcho, PacketType.LinkEchoReply,
                PacketType.LinkProbe, PacketType.LinkProbeEnd, PacketType.LinkProbeResult);
        }

        public async Task<LinkTestResult> RunAsync(string fp, IProgress<string>? progress, CancellationToken ct, int probeMB = 64)
        {
            // ---- Latency ----
            var rtts = new List<long>();
            int lost = 0;
            for (int i = 0; i < 20; i++)
            {
                ct.ThrowIfCancellationRequested();
                long seq = Interlocked.Increment(ref _echoSeq);
                var tcs = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
                _echo[seq] = tcs;
                var p = new byte[16];
                BinaryPrimitives.WriteInt64LittleEndian(p, seq);
                long t0 = Stopwatch.GetTimestamp();
                BinaryPrimitives.WriteInt64LittleEndian(p.AsSpan(8), t0);
                await _msg.SendAsync(fp, PacketType.LinkEcho, p, ct).ConfigureAwait(false);
                try
                {
                    await tcs.Task.WaitAsync(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                    rtts.Add((long)Stopwatch.GetElapsedTime(t0).TotalMicroseconds);
                }
                catch (TimeoutException) { lost++; }
                finally { _echo.TryRemove(seq, out _); }
                progress?.Report($"echo {i + 1}/20");
                await Task.Delay(50, ct).ConfigureAwait(false);
            }

            // ---- Throughput ----
            var id = Guid.NewGuid();
            var resTcs = new TaskCompletionSource<(long, long)>(TaskCreationOptions.RunContinuationsAsynchronously);
            _results[id] = resTcs;
            const int chunk = 128 * 1024;
            long total = (long)probeMB << 20;
            byte[] random = RandomNumberGenerator.GetBytes(chunk);
            var sw = Stopwatch.StartNew();
            for (long sent = 0; sent < total; sent += chunk)
            {
                ct.ThrowIfCancellationRequested();
                byte[] buf = ArrayPool<byte>.Shared.Rent(16 + chunk);
                id.TryWriteBytes(buf);
                random.CopyTo(buf, 16);
                await _msg.SendBulkAsync(fp, PacketType.LinkProbe, buf, 16 + chunk, ct).ConfigureAwait(false);
                if ((sent / chunk) % 32 == 0) progress?.Report($"throughput {sent * 100 / total}%");
            }
            await _msg.SendAsync(fp, PacketType.LinkProbeEnd, id.ToByteArray(), ct).ConfigureAwait(false);
            (long bytes, long ms) = await resTcs.Task.WaitAsync(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            _results.TryRemove(id, out _);
            double secs = Math.Max(ms, 1) / 1000.0;

            double ToMs(long us) => us / 1000.0;
            var rttMs = rtts.Select(ToMs).ToList();
            return new LinkTestResult(
                rttMs.Count > 0 ? rttMs.Min() : -1, rttMs.Count > 0 ? rttMs.Average() : -1, rttMs.Count > 0 ? rttMs.Max() : -1,
                rttMs.Count < 2 ? 0 : Enumerable.Range(1, rttMs.Count - 1).Average(i => Math.Abs(rttMs[i] - rttMs[i - 1])),
                lost, bytes / secs / 1048576.0, bytes, secs);
        }

        private ValueTask HandleAsync(string fp, PacketType type, ReadOnlyMemory<byte> payload)
        {
            switch (type)
            {
                case PacketType.LinkEcho when payload.Length == 16:
                    _ = SafeSend(fp, PacketType.LinkEchoReply, payload.ToArray()); // không await trong reader loop
                    break;
                case PacketType.LinkEchoReply when payload.Length == 16:
                    if (_echo.TryGetValue(BinaryPrimitives.ReadInt64LittleEndian(payload.Span), out var tcs)) tcs.TrySetResult(0);
                    break;
                case PacketType.LinkProbe when payload.Length >= 16:
                {
                    var id = new Guid(payload.Span[..16]);
                    _rx.AddOrUpdate(id, _ => (payload.Length - 16, Stopwatch.GetTimestamp()),
                                    (_, v) => (v.Bytes + payload.Length - 16, v.StartTick));
                    break;
                }
                case PacketType.LinkProbeEnd when payload.Length >= 16:
                {
                    var id = new Guid(payload.Span[..16]);
                    if (_rx.TryRemove(id, out var v))
                    {
                        var r = new byte[32];
                        id.TryWriteBytes(r);
                        BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(16), v.Bytes);
                        BinaryPrimitives.WriteInt64LittleEndian(r.AsSpan(24), (long)Stopwatch.GetElapsedTime(v.StartTick).TotalMilliseconds);
                        _ = SafeSend(fp, PacketType.LinkProbeResult, r);
                    }
                    break;
                }
                case PacketType.LinkProbeResult when payload.Length >= 32:
                {
                    var id = new Guid(payload.Span[..16]);
                    if (_results.TryGetValue(id, out var t))
                        t.TrySetResult((BinaryPrimitives.ReadInt64LittleEndian(payload.Span[16..]),
                                        BinaryPrimitives.ReadInt64LittleEndian(payload.Span[24..])));
                    break;
                }
            }
            return ValueTask.CompletedTask;
        }

        private async Task SafeSend(string fp, PacketType t, byte[] p)
        {
            try { await _msg.SendAsync(fp, t, p).ConfigureAwait(false); } catch { }
        }

        public void Dispose() => _msg.UnregisterHandler(PacketType.LinkEcho, PacketType.LinkEchoReply,
            PacketType.LinkProbe, PacketType.LinkProbeEnd, PacketType.LinkProbeResult);
    }
}
