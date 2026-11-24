using System.Diagnostics;
using System.IO;
using System.Net;
using networkApp;
using networkApp.Security;

static class SecurityTests
{
    public static async Task<int> RunAsync()
    {
        int fail = 0;
        Console.WriteLine("=== ATTACK LAB ===");
        var sw = Stopwatch.StartNew();
        await new SecurityLab().RunAllAsync(r =>
        {
            if (r.Outcome != LabOutcome.Blocked) fail++;
            Console.WriteLine($"[{r.Outcome,-10}] {r.Attack}  ({r.ElapsedMs} ms)\n             {r.Evidence}");
        }, CancellationToken.None);
        Console.WriteLine($"lab total {sw.ElapsedMilliseconds} ms");

        Console.WriteLine("\n=== HOST AUDIT ===");
        sw.Restart();
        var rep = HostAudit.Run();
        Console.WriteLine($"score {rep.Score}/100 in {sw.ElapsedMilliseconds} ms");
        Console.WriteLine("firewall: " + string.Join(", ", rep.Firewall.Select(kv => $"{kv.Key}={kv.Value?.ToString() ?? "?"}")));
        Console.WriteLine("networks: " + string.Join(", ", rep.Networks.Select(n => $"{n.Name}={n.Category}")));
        Console.WriteLine("wifi: " + (rep.Wifi is null ? "(none)" : $"{rep.Wifi.Ssid} {rep.Wifi.Authentication} {rep.Wifi.Cipher} {rep.Wifi.Signal} {rep.Wifi.Band}"));
        Console.WriteLine($"listeners: {rep.Listeners.Count} (exposed TCP: {rep.Listeners.Count(l => l.Protocol.StartsWith("TCP") && l.IsExposed)})");
        foreach (var l in rep.Listeners.Where(l => l.Protocol == "TCP").Take(8)) Console.WriteLine($"   {l.Protocol} {l.Address}:{l.Port} {l.ProcessName}({l.Pid})");
        foreach (var f in rep.Findings) Console.WriteLine($"   [{f.Severity}] {f.Title} — {f.Detail}");
        if (rep.Listeners.Count == 0) { fail++; Console.WriteLine("FAIL: no listeners parsed"); }

        Console.WriteLine("\n=== ARP / THREAT MONITOR ===");
        var arp = NetNative.GetArpTable();
        Console.WriteLine($"arp entries: {arp.Count}, usable: {arp.Count(a => a.IsUsable)}");
        foreach (var a in arp.Where(a => a.IsUsable && !Knowledge.IsMulticastOrBroadcastMac(a.Mac)).Take(6))
            Console.WriteLine($"   {a.Address,-16} {a.Mac} {a.Type} {Knowledge.Vendor(a.Mac)}");
        var log = new SecurityLog();
        log.Added += e => Console.WriteLine($"   event [{e.Severity}] {e.Title}: {e.Detail}");
        using var mon = new ThreatMonitor(log);
        mon.Tick(); mon.Tick();
        Console.WriteLine($"monitor: devices={mon.DeviceCount} gateway={mon.GatewayInfo}");

        Console.WriteLine("\n=== LAN SCANNER (host-only adapter only) ===");
        var iface = DiscoveryService.EnumerateInterfaces().FirstOrDefault(i => i.Address.ToString().StartsWith("192.168.56."));
        if (iface is null) Console.WriteLine("no host-only adapter — skipped");
        else
        {
            sw.Restart();
            var hosts = await new LanScanner().ScanAsync(iface, false, new Progress<ScanProgress>(_ => { }), _ => { }, CancellationToken.None);
            Console.WriteLine($"{hosts.Count} host(s) in {sw.ElapsedMilliseconds} ms on {iface}");
            foreach (var h in hosts)
            {
                Console.WriteLine($"   {h.Ip} mac={h.Mac} vendor={h.Vendor} name={h.HostName} ping={h.PingMs} self={h.IsSelf} risk={h.MaxRisk}");
                foreach (var s in h.Services) Console.WriteLine($"      {s.Port}/{s.Service} [{s.Risk}] {s.Banner} {string.Join(" | ", s.Issues)}");
            }
        }

        Console.WriteLine("\n=== PROBE localhost services ===");
        foreach (var p in Knowledge.Ports)
        {
            var f = await LanScanner.ProbeAsync(IPAddress.Loopback, p, CancellationToken.None);
            if (f is not null) Console.WriteLine($"   {f.Port}/{f.Service} [{f.Risk}] {f.Banner} {string.Join(" | ", f.Issues)}");
        }

        Console.WriteLine("\n=== LINK TEST over encrypted channel ===");
        string root = Path.Combine(Path.GetTempPath(), "hlc-link-" + Environment.ProcessId);
        using (var ca = new CryptoService(Path.Combine(root, "a")))
        using (var cb = new CryptoService(Path.Combine(root, "b")))
        {
            using var ma = new MessagingService(ca, "a", 0, IPAddress.Loopback);
            using var mb = new MessagingService(cb, "b", 0, IPAddress.Loopback);
            ma.Start(); mb.Start();
            using var la = new LinkTestService(ma);
            using var lb = new LinkTestService(mb);
            ma.AddEndpoint(cb.Fingerprint, new IPEndPoint(IPAddress.Loopback, mb.ListenPort));
            var traces = 0;
            ma.TraceEnabled = true;
            ma.FrameTraced += _ => Interlocked.Increment(ref traces);
            var res = await la.RunAsync(cb.Fingerprint, null, CancellationToken.None, 128);
            Console.WriteLine($"   RTT {res.RttMinMs:0.00}/{res.RttAvgMs:0.00}/{res.RttMaxMs:0.00} ms jitter {res.JitterMs:0.00} lost {res.EchoLost} · {res.ThroughputMBps:0} MB/s ({res.Bytes >> 20} MB in {res.Seconds:0.00}s) · traces {traces}");
            if (res.ThroughputMBps <= 0 || traces == 0) fail++;
        }
        try { Directory.Delete(root, true); } catch { }

        Console.WriteLine(fail == 0 ? "\nSECURITY SUITE PASSED" : $"\nSECURITY SUITE: {fail} FAILURE(S)");
        return fail;
    }
}
