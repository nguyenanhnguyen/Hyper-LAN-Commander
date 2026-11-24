using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace networkApp.Security
{
    /// <summary>Xuất báo cáo kiểm định thành MỘT file HTML tự chứa (gửi email / in PDF được).</summary>
    public static class ReportExporter
    {
        public static string Export(string folder, string machine, string fingerprint, HostAuditReport? host,
                                    IReadOnlyList<HostResult> lan, IReadOnlyList<LabResult> lab,
                                    IReadOnlyList<SecurityEvent> events)
        {
            Directory.CreateDirectory(folder);
            string path = Path.Combine(folder, $"HyperLAN-security-report-{DateTime.Now:yyyyMMdd-HHmmss}.html");
            var sb = new StringBuilder();
            string E(string? s) => WebUtility.HtmlEncode(s ?? "");
            string Sev(Severity s) => $"<span class='sev s{(int)s}'>{E(Knowledge.SeverityLabel(s))}</span>";

            sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>Hyper-LAN Security Report</title><style>")
              .Append("body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#0f172a;background:#f8fafc}h1{margin:0}")
              .Append("h2{margin-top:32px;border-bottom:2px solid #e2e8f0;padding-bottom:6px}table{border-collapse:collapse;width:100%;background:#fff}")
              .Append("td,th{border:1px solid #e2e8f0;padding:6px 10px;text-align:left;vertical-align:top;font-size:13px}th{background:#f1f5f9}")
              .Append(".sev{font-weight:700;font-size:11px;padding:2px 6px;border-radius:4px;color:#fff}.s0{background:#64748b}.s1{background:#0ea5e9}")
              .Append(".s2{background:#f59e0b}.s3{background:#ef4444}.s4{background:#7f1d1d}.ok{color:#15803d;font-weight:700}.bad{color:#b91c1c;font-weight:700}")
              .Append(".score{font-size:48px;font-weight:800}.muted{color:#64748b}code{font-family:Consolas,monospace}</style></head><body>");

            sb.Append($"<h1>Hyper-LAN Commander — {E(Localization.Pick("Báo cáo an ninh mạng", "Network Security Report"))}</h1>")
              .Append($"<p class='muted'>{DateTime.Now:yyyy-MM-dd HH:mm:ss} · {E(machine)} · ID <code>{E(fingerprint)}</code></p>");

            if (host is not null)
            {
                sb.Append($"<h2>{E(Localization.Pick("Máy này", "This device"))}</h2><div class='score'>{host.Score}/100</div>")
                  .Append("<p>Firewall: ").Append(string.Join(" · ", host.Firewall.Select(kv => $"{kv.Key} = {(kv.Value is null ? "?" : kv.Value.Value ? "ON" : "<b class='bad'>OFF</b>")}")))
                  .Append("</p><p>").Append(E(string.Join(" · ", host.Networks.Select(n => $"{n.Name} ({n.Category})")))).Append("</p>")
                  .Append("<table><tr><th></th><th>Finding</th><th>Detail</th></tr>");
                foreach (var f in host.Findings) sb.Append($"<tr><td>{Sev(f.Severity)}</td><td>{E(f.Title)}</td><td>{E(f.Detail)}</td></tr>");
                sb.Append("</table>");
            }

            if (lan.Count > 0)
            {
                sb.Append($"<h2>{E(Localization.Pick("Kiểm định LAN", "LAN audit"))} — {lan.Count} host</h2>")
                  .Append("<table><tr><th>IP</th><th>MAC / vendor</th><th>Name</th><th>Open services</th><th>Risk</th></tr>");
                foreach (var h in lan)
                {
                    string svcs = string.Join("<br>", h.Services.Select(s =>
                        $"{Sev(s.Risk)} <b>{s.Port}/{E(s.Service)}</b> {E(s.Banner)}" +
                        string.Concat(s.Issues.Select(i => $"<br>&nbsp;&nbsp;⚠ {E(i)}"))));
                    sb.Append($"<tr><td>{E(h.Ip.ToString())}{(h.IsSelf ? " (self)" : "")}{(h.IsGateway ? " (gateway)" : "")}</td>")
                      .Append($"<td><code>{E(h.Mac)}</code><br>{E(h.Vendor)}</td><td>{E(h.HostName)}</td><td>{svcs}</td><td>{Sev(h.MaxRisk)}</td></tr>");
                }
                sb.Append("</table>");
            }

            if (lab.Count > 0)
            {
                int blocked = lab.Count(r => r.Outcome == LabOutcome.Blocked);
                sb.Append($"<h2>Attack Lab — {blocked}/{lab.Count} {E(Localization.Pick("bị chặn", "blocked"))}</h2>")
                  .Append("<table><tr><th>Attack</th><th>Defense</th><th>Result</th><th>Evidence</th></tr>");
                foreach (var r in lab)
                    sb.Append($"<tr><td><b>{E(r.Attack)}</b><br><span class='muted'>{E(r.Technique)}</span></td><td>{E(r.Defense)}</td>")
                      .Append($"<td class='{(r.Outcome == LabOutcome.Blocked ? "ok" : "bad")}'>{r.Outcome}</td><td>{E(r.Evidence)}</td></tr>");
                sb.Append("</table>");
            }

            if (events.Count > 0)
            {
                sb.Append($"<h2>{E(Localization.Pick("Nhật ký sự kiện an ninh", "Security event log"))}</h2>")
                  .Append("<table><tr><th>Time</th><th></th><th>Category</th><th>Event</th><th>Detail</th></tr>");
                foreach (var ev in events.Reverse().Take(500))
                    sb.Append($"<tr><td>{ev.Time:HH:mm:ss}</td><td>{Sev(ev.Severity)}</td><td>{ev.Category}</td><td>{E(ev.Title)}</td><td>{E(ev.Detail)}</td></tr>");
                sb.Append("</table>");
            }

            sb.Append("<p class='muted' style='margin-top:32px'>Generated by Hyper-LAN Commander · non-intrusive audit (no credential guessing, no exploit payloads).</p></body></html>");
            File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
            return path;
        }
    }
}
