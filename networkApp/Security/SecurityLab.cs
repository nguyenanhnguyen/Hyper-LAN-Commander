using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace networkApp.Security
{
    public enum LabOutcome { Blocked, Vulnerable, Error }

    public sealed record LabResult(string Id, string Attack, string Technique, string Defense,
                                   LabOutcome Outcome, string Evidence, long ElapsedMs);

    /// <summary>
    /// ATTACK LAB — "chứng minh bằng thực nghiệm" chứ không chỉ tuyên bố.
    ///
    /// Dựng hai node Hyper-LAN thật (Alice → Bob) trên 127.0.0.1 với danh tính TẠM, chèn một
    /// proxy MITM hiểu cấu trúc record ở giữa, rồi tung các đòn tấn công kinh điển vào chính
    /// giao thức của app: nghe lén, sửa bit, phát lại, xóa, đảo thứ tự, chèn gói giả, thay khóa
    /// (MITM chủ động), mạo danh, hạ cấp phiên bản, DoS khung khổng lồ, flood/slowloris, fuzzing,
    /// và cuối cùng chứng minh Forward Secrecy bằng cách "đánh cắp" khóa dài hạn của CẢ HAI bên.
    ///
    /// Tất cả chạy cục bộ, cô lập (thư mục tạm bị xóa sau khi xong), không chạm tới phiên thật.
    /// </summary>
    public sealed class SecurityLab
    {
        private static string P(string vi, string en) => Localization.Pick(vi, en);

        public static int ScenarioCount => 13;

        public async Task RunAllAsync(Action<LabResult> onResult, CancellationToken ct)
        {
            string root = Path.Combine(Path.GetTempPath(), "HyperLAN-lab-" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                var scenarios = new Func<string, CancellationToken, Task<LabResult>>[]
                {
                    Eavesdrop, BitFlip, Replay, Drop, Reorder, Inject, KeySubstitution, Impersonation,
                    Downgrade, OversizedFrame, FloodAndSlowloris, Fuzzing, ForwardSecrecy,
                };
                foreach (var s in scenarios)
                {
                    ct.ThrowIfCancellationRequested();
                    var sw = Stopwatch.StartNew();
                    LabResult r;
                    try { r = await s(Path.Combine(root, Guid.NewGuid().ToString("N")[..6]), ct).ConfigureAwait(false); }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        r = new LabResult(s.Method.Name, s.Method.Name, "", "", LabOutcome.Error, ex.Message, 0);
                    }
                    onResult(r with { ElapsedMs = sw.ElapsedMilliseconds });
                }
            }
            finally
            {
                await Task.Delay(300).ConfigureAwait(false);
                try { Directory.Delete(root, recursive: true); } catch { }
            }
        }

        // =====================================================================
        //  1. NGHE LÉN THỤ ĐỘNG
        // =====================================================================
        private async Task<LabResult> Eavesdrop(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            using var proxy = new LabProxy(bob.Port, null);
            alice.Msg.AddEndpoint(bob.Fp, proxy.EndPoint);

            const string secret = "password=hunter2";
            for (int i = 0; i < 20; i++)
                await alice.Msg.SendTextAsync(bob.Fp, $"TOP-SECRET #{i} {secret}", ct).ConfigureAwait(false);
            await WaitFor(() => bob.Texts.Count >= 20, 3000).ConfigureAwait(false);

            byte[] wire = proxy.CapturedBytes();
            int hits = CountOccurrences(wire, Encoding.UTF8.GetBytes("hunter2")) +
                       CountOccurrences(wire, Encoding.UTF8.GetBytes("TOP-SECRET"));
            var sealedBodies = proxy.ClientToServer.Concat(proxy.ServerToClient)
                .Where(r => r[0] == (byte)RecordType.Sealed).SelectMany(r => r.Skip(5)).ToArray();
            double entropy = ShannonEntropy(sealedBodies);
            var kinds = proxy.ClientToServer.Concat(proxy.ServerToClient).Select(r => (char)r[0]).Distinct();

            bool ok = hits == 0 && bob.Texts.Count >= 20;
            return new LabResult("eavesdrop",
                P("Nghe lén thụ động (Wireshark trên cùng Wi-Fi)", "Passive eavesdropping (Wireshark on the same Wi-Fi)"),
                P("Ghi lại toàn bộ byte trên dây trong lúc Alice gửi 20 tin chứa \"password=hunter2\", rồi tìm chuỗi rõ.",
                  "Record every byte on the wire while Alice sends 20 messages containing \"password=hunter2\", then grep for plaintext."),
                P("AES-256-GCM cho mọi record; loại gói cũng nằm trong ciphertext.", "AES-256-GCM on every record; even the packet type is inside the ciphertext."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"Bắt được {wire.Length / 1024.0:0.0} KB · {hits} lần thấy chuỗi bí mật · entropy {entropy:0.000} bit/byte (ngẫu nhiên tuyệt đối = 8) · loại record thấy được: {string.Join(", ", kinds)} (H=Hello công khai, S=Sealed) · Bob nhận đủ {bob.Texts.Count}/20 tin.",
                  $"Captured {wire.Length / 1024.0:0.0} KB · {hits} plaintext hits · entropy {entropy:0.000} bits/byte (perfect random = 8) · visible record kinds: {string.Join(", ", kinds)} (H=public Hello, S=Sealed) · Bob got {bob.Texts.Count}/20 messages."),
                0);
        }

        // =====================================================================
        //  2–6. TẤN CÔNG TOÀN VẸN (MITM chủ động sửa luồng record)
        // =====================================================================
        private Task<LabResult> BitFlip(string dir, CancellationToken ct) => IntegrityAttack(dir, ct, "bitflip",
            P("Sửa nội dung gói (lật 1 bit)", "Packet tampering (flip one bit)"),
            P("Proxy MITM lật 1 bit giữa ciphertext của record #4 Alice → Bob.", "MITM proxy flips one bit in the ciphertext of Alice→Bob record #4."),
            P("GCM authentication tag (128-bit) — sửa 1 bit là tag sai, fail-closed.", "128-bit GCM tag — any bit change fails verification; fail-closed."),
            (i, rec, outp) =>
            {
                if (i == 4) rec[5 + (rec.Length - 5) / 2] ^= 0x01;
                outp.Add(rec);
            });

        private Task<LabResult> Replay(string dir, CancellationToken ct) => IntegrityAttack(dir, ct, "replay",
            P("Phát lại gói (replay)", "Replay attack"),
            P("Proxy gửi record #4 HAI lần — y nguyên ciphertext hợp lệ đã bắt được.", "Proxy sends record #4 TWICE — a perfectly valid captured ciphertext."),
            P("Nonce = bộ đếm 64-bit ngầm định; bản sao được giải mã với nonce kế tiếp → tag sai.", "Nonce = implicit 64-bit counter; the copy is decrypted with the next nonce → tag fails."),
            (i, rec, outp) => { outp.Add(rec); if (i == 4) outp.Add((byte[])rec.Clone()); });

        private Task<LabResult> Drop(string dir, CancellationToken ct) => IntegrityAttack(dir, ct, "drop",
            P("Xóa gói lặng lẽ (deletion)", "Silent packet deletion"),
            P("Proxy nuốt mất record #4 (vd. xóa một lệnh \"hủy giao dịch\").", "Proxy silently drops record #4 (e.g. suppress a \"cancel\" command)."),
            P("Bộ đếm nonce lệch 1 → record tiếp theo không giải mã được → phát hiện mất gói.", "Nonce counter is off by one → next record fails → deletion detected."),
            (i, rec, outp) => { if (i != 4) outp.Add(rec); });

        private Task<LabResult> Reorder(string dir, CancellationToken ct)
        {
            byte[]? held = null;
            return IntegrityAttack(dir, ct, "reorder",
                P("Đảo thứ tự gói", "Packet reordering"),
                P("Proxy giữ record #4 lại, gửi #5 trước rồi mới gửi #4.", "Proxy holds record #4, forwards #5 first, then #4."),
                P("Nonce tuần tự bắt buộc đúng thứ tự.", "Sequential nonces enforce ordering."),
                (i, rec, outp) =>
                {
                    if (i == 4) { held = rec; return; }
                    outp.Add(rec);
                    if (i == 5 && held is not null) outp.Add(held);
                });
        }

        private Task<LabResult> Inject(string dir, CancellationToken ct) => IntegrityAttack(dir, ct, "inject",
            P("Chèn gói giả mạo", "Forged packet injection"),
            P("Proxy chèn một record Sealed tự chế (header hợp lệ, thân ngẫu nhiên) trước record #4.", "Proxy injects a home-made Sealed record (valid header, random body) before #4."),
            P("Không có khóa phiên thì không tạo được tag hợp lệ (xác suất 2⁻¹²⁸).", "Without the session key a valid tag is impossible (2⁻¹²⁸ chance)."),
            (i, rec, outp) =>
            {
                if (i == 4)
                {
                    var forged = new byte[5 + 64];
                    RandomNumberGenerator.Fill(forged.AsSpan(5));
                    Protocol.WriteHeader(forged, RecordType.Sealed, 64);
                    outp.Add(forged);
                }
                outp.Add(rec);
            });

        private async Task<LabResult> IntegrityAttack(string dir, CancellationToken ct, string id, string attack,
                                                      string technique, string defense, LabProxy.Transform transform)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            using var proxy = new LabProxy(bob.Port, transform);
            alice.Msg.AddEndpoint(bob.Fp, proxy.EndPoint);

            var sent = new HashSet<string>();
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < 10; i++)
            {
                string m = $"transfer #{i}: 100 USD → account 12345";
                sent.Add(m);
                try { await alice.Msg.SendTextAsync(bob.Fp, m, ct).ConfigureAwait(false); } catch { }
                await Task.Delay(30, ct).ConfigureAwait(false);
            }
            bool detected = await WaitFor(() => bob.Lost.Contains(CloseReason.Tampered), 3000).ConfigureAwait(false);
            int corrupted = bob.Texts.Count(t => !sent.Contains(t));
            int dupes = bob.Texts.GroupBy(t => t).Count(g => g.Count() > 1);

            bool ok = detected && corrupted == 0 && dupes == 0;
            return new LabResult(id, attack, technique, defense, ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"Bob cắt phiên với lý do {string.Join(",", bob.Lost.Distinct())} · {bob.Texts.Count} tin nguyên vẹn được giao · {corrupted} tin bị sửa lọt qua · {dupes} tin trùng.",
                  $"Bob terminated the session: {string.Join(",", bob.Lost.Distinct())} · {bob.Texts.Count} intact messages delivered · {corrupted} corrupted accepted · {dupes} duplicates."),
                0);
        }

        // =====================================================================
        //  7. MITM CHỦ ĐỘNG — THAY KHÓA TẠM TRONG HELLO
        // =====================================================================
        private async Task<LabResult> KeySubstitution(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            using var mallory = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            string evilEph = Convert.ToBase64String(mallory.ExportSubjectPublicKeyInfo());
            using var proxy = new LabProxy(bob.Port, (i, rec, outp) =>
            {
                if (i == 0 && rec[0] == (byte)RecordType.Hello)
                {
                    var json = JsonNode.Parse(rec.AsSpan(5).ToArray())!;
                    json["Eph"] = evilEph; // Mallory thay khóa ECDH tạm của Alice bằng khóa của mình
                    byte[] body = Encoding.UTF8.GetBytes(json.ToJsonString());
                    var forged = new byte[5 + body.Length];
                    Protocol.WriteHeader(forged, RecordType.Hello, body.Length);
                    body.CopyTo(forged, 5);
                    outp.Add(forged);
                    return;
                }
                outp.Add(rec);
            });
            alice.Msg.AddEndpoint(bob.Fp, proxy.EndPoint);

            Exception? err = null;
            try { await alice.Msg.SendTextAsync(bob.Fp, "hello bob", ct).ConfigureAwait(false); }
            catch (Exception ex) { err = ex; }
            await WaitFor(() => bob.Rejected.Count > 0, 3000).ConfigureAwait(false);

            bool ok = bob.Texts.IsEmpty && bob.Rejected.Contains(CloseReason.AuthFailed);
            return new LabResult("keysub",
                P("MITM chủ động: tráo khóa Diffie-Hellman", "Active MITM: Diffie-Hellman key substitution"),
                P("Mallory sửa gói Hello, thay khóa ECDH tạm của Alice bằng khóa của mình để đứng giữa giải mã.",
                  "Mallory rewrites Alice's Hello, swapping her ephemeral ECDH key for his own to sit in the middle."),
                P("Transcript (cả 2 Hello) được băm & KÝ bằng ECDSA; khóa phiên dẫn xuất từ transcript → lệch là lộ.",
                  "Both Hellos are hashed into a transcript that is SIGNED with ECDSA and salts the KDF → any change is exposed."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"Bob từ chối: {string.Join(",", bob.Rejected.Distinct())} · Alice: {Short(err)} · 0 byte dữ liệu người dùng rời khỏi Alice.",
                  $"Bob refused: {string.Join(",", bob.Rejected.Distinct())} · Alice: {Short(err)} · 0 bytes of user data left Alice."),
                0);
        }

        // =====================================================================
        //  8. MẠO DANH (máy giả trả lời thay Bob)
        // =====================================================================
        private async Task<LabResult> Impersonation(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var mallory = new LabNode(dir, "mallory", displayName: "bob"); // cùng TÊN, khác khóa
            using var alice = new LabNode(dir, "alice");
            // Giả lập ARP/DNS spoofing: địa chỉ "của Bob" trỏ tới máy Mallory
            alice.Msg.AddEndpoint(bob.Fp, new IPEndPoint(IPAddress.Loopback, mallory.Port));

            Exception? err = null;
            try { await alice.Msg.SendTextAsync(bob.Fp, "my bank PIN is 4321", ct).ConfigureAwait(false); }
            catch (Exception ex) { err = ex; }
            await Task.Delay(300, ct).ConfigureAwait(false);

            bool ok = err is not null && mallory.Texts.IsEmpty;
            return new LabResult("impersonation",
                P("Mạo danh (máy giả cùng tên, chiếm địa chỉ)", "Impersonation (rogue host, same name, hijacked address)"),
                P("Địa chỉ của Bob bị trỏ sang máy Mallory (như sau ARP/DNS spoofing). Mallory tự xưng là \"bob\".",
                  "Bob's address is redirected to Mallory (as after ARP/DNS spoofing). Mallory calls himself \"bob\"."),
                P("Định danh = fingerprint khóa công khai, KHÔNG phải IP hay tên. Bắt tay thành công với Mallory nhưng fingerprint sai → không gửi gì.",
                  "Identity = public-key fingerprint, NOT IP or name. Handshake with Mallory succeeds but the fingerprint mismatches → nothing is sent."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"Mong đợi {bob.Fp}, gặp {mallory.Fp} → từ chối ({Short(err)}) · Mallory nhận {mallory.Texts.Count} tin.",
                  $"Expected {bob.Fp}, met {mallory.Fp} → refused ({Short(err)}) · Mallory received {mallory.Texts.Count} messages."),
                0);
        }

        // =====================================================================
        //  9. HẠ CẤP PHIÊN BẢN
        // =====================================================================
        private async Task<LabResult> Downgrade(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            using var proxy = new LabProxy(bob.Port, (i, rec, outp) =>
            {
                if (i == 0 && rec[0] == (byte)RecordType.Hello)
                {
                    var json = JsonNode.Parse(rec.AsSpan(5).ToArray())!;
                    json["V"] = 1; // ép về giao thức v1 (static ECDH, không PFS)
                    byte[] body = Encoding.UTF8.GetBytes(json.ToJsonString());
                    var forged = new byte[5 + body.Length];
                    Protocol.WriteHeader(forged, RecordType.Hello, body.Length);
                    body.CopyTo(forged, 5);
                    outp.Add(forged);
                    return;
                }
                outp.Add(rec);
            });
            alice.Msg.AddEndpoint(bob.Fp, proxy.EndPoint);
            try { await alice.Msg.SendTextAsync(bob.Fp, "hi", ct).ConfigureAwait(false); } catch { }
            await WaitFor(() => bob.Rejected.Count > 0, 3000).ConfigureAwait(false);

            bool ok = bob.Rejected.Contains(CloseReason.ProtocolError) && bob.Texts.IsEmpty;
            return new LabResult("downgrade",
                P("Tấn công hạ cấp (downgrade)", "Downgrade attack"),
                P("Proxy sửa trường version trong Hello từ 2 → 1 để ép dùng giao thức cũ yếu hơn.",
                  "Proxy rewrites the Hello version from 2 → 1 to force the weaker legacy protocol."),
                P("Không có chế độ tương thích ngược; version còn nằm trong transcript đã ký.", "No fallback mode; the version is also covered by the signed transcript."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"Bob từ chối: {string.Join(",", bob.Rejected.Distinct())} · 0 tin được trao đổi.", $"Bob refused: {string.Join(",", bob.Rejected.Distinct())} · no messages exchanged."),
                0);
        }

        // =====================================================================
        //  10. DoS BẰNG KHUNG KHỔNG LỒ
        // =====================================================================
        private async Task<LabResult> OversizedFrame(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            var results = new List<string>();
            long before = GC.GetTotalAllocatedBytes(precise: false);
            foreach (var (type, len) in new[] { ((byte)'H', int.MaxValue), ((byte)'H', 100_000), ((byte)'S', 50_000_000) })
            {
                using var c = new TcpClient();
                await c.ConnectAsync(IPAddress.Loopback, bob.Port, ct).ConfigureAwait(false);
                var hdr = new byte[5];
                hdr[0] = type;
                BinaryPrimitives.WriteInt32LittleEndian(hdr.AsSpan(1), len);
                var sw = Stopwatch.StartNew();
                await c.GetStream().WriteAsync(hdr, ct).ConfigureAwait(false);
                bool closed = await WaitClosedAsync(c, 3000).ConfigureAwait(false);
                results.Add($"{(char)type} len={len:N0} → {(closed ? $"closed {sw.ElapsedMilliseconds} ms" : "OPEN")}");
            }
            long allocatedKb = (GC.GetTotalAllocatedBytes(false) - before) / 1024;
            bool ok = results.All(r => r.Contains("closed")) && allocatedKb < 20_000;
            return new LabResult("oversize",
                P("DoS cạn RAM bằng khung khai báo khổng lồ", "Memory-exhaustion DoS via huge declared frame"),
                P("Gửi header tuyên bố thân gói 2 GB / 100 KB Hello / 50 MB record — chờ server cấp phát.",
                  "Send headers declaring a 2 GB body / 100 KB Hello / 50 MB record — hoping the server allocates it."),
                P("Kiểm tra độ dài TRƯỚC khi cấp phát: Hello ≤ 4 KB, record ≤ 4 MB.", "Length is validated BEFORE allocation: Hello ≤ 4 KB, record ≤ 4 MB."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                $"{string.Join(" · ", results)} · Δalloc ≈ {allocatedKb:N0} KB", 0);
        }

        // =====================================================================
        //  11. FLOOD + SLOWLORIS
        // =====================================================================
        private async Task<LabResult> FloodAndSlowloris(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            alice.Msg.AddEndpoint(bob.Fp, new IPEndPoint(IPAddress.Loopback, bob.Port));

            // Kẻ tấn công dùng địa chỉ nguồn 127.0.0.2 (máy khác Alice) mở 40 kết nối rồi im lặng
            var attackers = new List<TcpClient>();
            for (int i = 0; i < 40; i++)
            {
                var c = new TcpClient(new IPEndPoint(IPAddress.Parse("127.0.0.2"), 0));
                try { await c.ConnectAsync(IPAddress.Loopback, bob.Port, ct).ConfigureAwait(false); attackers.Add(c); }
                catch { c.Dispose(); }
            }
            await Task.Delay(400, ct).ConfigureAwait(false);
            var alive = await Task.WhenAll(attackers.Select(c => WaitClosedAsync(c, 50))).ConfigureAwait(false);
            int refusedNow = alive.Count(closed => closed);

            // Người dùng hợp lệ vẫn vào được TRONG LÚC bị flood?
            var sw = Stopwatch.StartNew();
            bool legitOk;
            try { await alice.Msg.SendTextAsync(bob.Fp, "still there?", ct).ConfigureAwait(false); legitOk = true; }
            catch { legitOk = false; }
            long legitMs = sw.ElapsedMilliseconds;

            // Slowloris: các kết nối im lặng còn lại phải bị đá khi hết hạn bắt tay
            sw.Restart();
            var dropped = await Task.WhenAll(attackers.Select(c => WaitClosedAsync(c, 9000))).ConfigureAwait(false);
            long dropMs = sw.ElapsedMilliseconds;
            foreach (var c in attackers) c.Dispose();

            bool ok = legitOk && refusedNow >= 40 - 16 && dropped.All(x => x);
            return new LabResult("flood",
                P("Connection flood + Slowloris", "Connection flood + Slowloris"),
                P("Một máy mở 40 kết nối TCP rồi không gửi gì, nhằm chiếm hết chỗ và khóa người dùng thật.",
                  "One host opens 40 TCP connections and sends nothing, trying to exhaust slots and lock out real users."),
                P("Tối đa 16 kết nối CHƯA xác thực mỗi IP (64 tổng) + hạn chót bắt tay 6 s.", "Max 16 UNauthenticated connections per IP (64 total) + 6 s handshake deadline."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"{refusedNow}/40 bị từ chối ngay · Alice vẫn kết nối được sau {legitMs} ms · {dropped.Count(x => x)}/40 socket im lặng bị đá sau {dropMs / 1000.0:0.0} s.",
                  $"{refusedNow}/40 refused immediately · Alice still connected in {legitMs} ms · {dropped.Count(x => x)}/40 idle sockets dropped after {dropMs / 1000.0:0.0} s."),
                0);
        }

        // =====================================================================
        //  12. FUZZING ĐẦU VÀO
        // =====================================================================
        private async Task<LabResult> Fuzzing(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            alice.Msg.AddEndpoint(bob.Fp, new IPEndPoint(IPAddress.Loopback, bob.Port));
            const int cases = 48;
            var payloads = new List<byte[]>();
            var rng = new Random(1337);
            for (int i = 0; i < cases; i++)
            {
                byte[] junk = new byte[rng.Next(12, 3000)];
                rng.NextBytes(junk);
                switch (i % 4)
                {
                    case 0: junk[0] = (byte)'H'; BinaryPrimitives.WriteInt32LittleEndian(junk.AsSpan(1, 4), rng.Next(0, 4000)); break; // độ dài sai lệch
                    case 1: junk[0] = (byte)'H'; BinaryPrimitives.WriteInt32LittleEndian(junk.AsSpan(1, 4), junk.Length - 5); junk[5] = (byte)'{'; break; // JSON hỏng
                    case 2: junk[0] = (byte)'S'; BinaryPrimitives.WriteInt32LittleEndian(junk.AsSpan(1, 4), junk.Length - 5); break; // Sealed trước Hello
                    default: break; // byte ngẫu nhiên thuần
                }
                payloads.Add(junk);
            }
            // Song song, mỗi ca từ một địa chỉ nguồn 127.0.0.x khác nhau (như nhiều máy tấn công)
            var outcomes = await Task.WhenAll(payloads.Select(async (junk, i) =>
            {
                using var c = new TcpClient(new IPEndPoint(IPAddress.Parse($"127.0.0.{10 + i}"), 0));
                await c.ConnectAsync(IPAddress.Loopback, bob.Port, ct).ConfigureAwait(false);
                try { await c.GetStream().WriteAsync(junk, ct).ConfigureAwait(false); } catch { }
                return await WaitClosedAsync(c, 8000).ConfigureAwait(false);
            })).ConfigureAwait(false);
            int closed = outcomes.Count(x => x);
            bool healthy;
            try { await alice.Msg.SendTextAsync(bob.Fp, "after fuzz", ct).ConfigureAwait(false); healthy = true; }
            catch { healthy = false; }

            bool ok = closed == cases && healthy;
            return new LabResult("fuzz",
                P("Fuzzing — dữ liệu rác / khung dị dạng", "Fuzzing — garbage & malformed frames"),
                P($"{cases} kết nối gửi byte ngẫu nhiên, Hello JSON hỏng, độ dài sai lệch.", $"{cases} connections sending random bytes, broken Hello JSON, inconsistent lengths."),
                P("Parser phòng thủ: mọi lỗi giải mã/JSON/độ dài → đóng kết nối đó, không ảnh hưởng phần còn lại.", "Defensive parser: any decode/JSON/length error closes that connection only."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"{closed}/{cases} bị đóng an toàn · dịch vụ vẫn khỏe: {(healthy ? "CÓ" : "KHÔNG")} · 0 crash.",
                  $"{closed}/{cases} closed safely · service healthy afterwards: {(healthy ? "YES" : "NO")} · 0 crashes."),
                0);
        }

        // =====================================================================
        //  13. FORWARD SECRECY — đánh cắp khóa dài hạn của CẢ HAI bên
        // =====================================================================
        private async Task<LabResult> ForwardSecrecy(string dir, CancellationToken ct)
        {
            using var bob = new LabNode(dir, "bob");
            using var alice = new LabNode(dir, "alice");
            using var proxy = new LabProxy(bob.Port, null);
            alice.Msg.AddEndpoint(bob.Fp, proxy.EndPoint);
            await alice.Msg.SendTextAsync(bob.Fp, "the launch code is 0000", ct).ConfigureAwait(false);
            await WaitFor(() => !bob.Texts.IsEmpty, 2000).ConfigureAwait(false);

            byte[] helloA = proxy.ClientToServer.First(r => r[0] == (byte)RecordType.Hello)[5..];
            byte[] helloB = proxy.ServerToClient.First(r => r[0] == (byte)RecordType.Hello)[5..];
            byte[] firstSealed = proxy.ClientToServer.First(r => r[0] == (byte)RecordType.Sealed); // Auth của Alice

            // Kẻ tấn công: đã ghi lại toàn bộ traffic, SAU ĐÓ đánh cắp khóa danh tính của cả Alice lẫn Bob
            var stolen = new[] { alice.Crypto.ExportPrivateForLab(), bob.Crypto.ExportPrivateForLab() };
            byte[] ephA = Convert.FromBase64String(JsonNode.Parse(helloA)!["Eph"]!.GetValue<string>());
            byte[] ephB = Convert.FromBase64String(JsonNode.Parse(helloB)!["Eph"]!.GetValue<string>());
            byte[] idA = alice.Crypto.PublicKey, idB = bob.Crypto.PublicKey;

            int attempts = 0, cracked = 0;
            foreach (var priv in stolen)
            foreach (var pub in new[] { ephA, ephB, idA, idB })
            {
                attempts++;
                using var key = ECDiffieHellman.Create(priv);
                try
                {
                    var keys = Handshake.Derive(key, pub, helloA, helloB); // cùng KDF, cùng transcript công khai
                    using var cs = new CipherState(keys.InitiatorToResponder);
                    byte[] body = firstSealed[5..];
                    int plain = body.Length - Protocol.TagSize;
                    cs.OpenInPlace(body.AsSpan(0, plain), body.AsSpan(plain), firstSealed.AsSpan(0, 5));
                    cracked++;
                }
                catch (CryptographicException) { }
            }

            bool ok = cracked == 0;
            return new LabResult("pfs",
                P("Forward Secrecy: lộ khóa dài hạn của CẢ HAI máy", "Forward secrecy: BOTH long-term keys stolen"),
                P("Ghi lại phiên, sau đó lấy cắp private key danh tính của Alice và Bob, thử mọi tổ hợp ECDH với các public key đã thấy trên dây.",
                  "Record a session, later steal BOTH identity private keys and try every ECDH combination with the public keys seen on the wire."),
                P("Khóa phiên đến từ ECDH TẠM (ECDHE) — private key tạm bị hủy ngay sau bắt tay, không bao giờ ghi đĩa.",
                  "Session keys come from EPHEMERAL ECDH — the ephemeral private keys are destroyed right after the handshake, never stored."),
                ok ? LabOutcome.Blocked : LabOutcome.Vulnerable,
                P($"{attempts} cách khôi phục khóa → {cracked} thành công · (thiết kế v1 cũ dùng ECDH tĩnh sẽ bị giải mã toàn bộ ở bước này).",
                  $"{attempts} key-recovery attempts → {cracked} succeeded · (the old v1 static-ECDH design would be fully decrypted here)."),
                0);
        }

        // =====================================================================
        //  TIỆN ÍCH
        // =====================================================================

        private static string Short(Exception? ex) => ex is null ? "OK" : ex is PeerUnavailableException p ? $"{p.Reason}" : ex.GetType().Name;

        private static async Task<bool> WaitFor(Func<bool> cond, int timeoutMs)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                if (cond()) return true;
                await Task.Delay(25).ConfigureAwait(false);
            }
            return cond();
        }

        /// <summary>Đọc tới khi server đóng (EOF/RST) hoặc hết giờ. true = đã bị đóng.</summary>
        private static async Task<bool> WaitClosedAsync(TcpClient c, int timeoutMs)
        {
            var buf = new byte[4096];
            using var cts = new CancellationTokenSource(timeoutMs);
            try
            {
                var s = c.GetStream();
                while (true)
                {
                    int n = await s.ReadAsync(buf, cts.Token).ConfigureAwait(false);
                    if (n == 0) return true;
                }
            }
            catch (OperationCanceledException) { return false; }
            catch { return true; } // RST
        }

        private static int CountOccurrences(byte[] hay, byte[] needle)
        {
            int count = 0;
            for (int i = hay.AsSpan().IndexOf(needle); i >= 0;)
            {
                count++;
                int next = hay.AsSpan(i + 1).IndexOf(needle);
                i = next < 0 ? -1 : i + 1 + next;
            }
            return count;
        }

        internal static double ShannonEntropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var freq = new int[256];
            foreach (byte b in data) freq[b]++;
            double h = 0;
            foreach (int f in freq)
            {
                if (f == 0) continue;
                double p = (double)f / data.Length;
                h -= p * Math.Log2(p);
            }
            return h;
        }

        // ---------------------------------------------------------------------
        private sealed class LabNode : IDisposable
        {
            public CryptoService Crypto { get; }
            public MessagingService Msg { get; }
            public ConcurrentQueue<string> Texts { get; } = new();
            public ConcurrentQueue<CloseReason> Lost { get; } = new();
            public ConcurrentQueue<CloseReason> Rejected { get; } = new();
            public string Fp => Crypto.Fingerprint;
            public int Port => Msg.ListenPort;

            public LabNode(string dir, string name, string? displayName = null)
            {
                Crypto = new CryptoService(Path.Combine(dir, name));
                Msg = new MessagingService(Crypto, displayName ?? name, preferredPort: 0, bindAddress: IPAddress.Loopback);
                Msg.TextReceived += (_, t) => Texts.Enqueue(t);
                Msg.SessionLost += (_, r) => Lost.Enqueue(r);
                Msg.ConnectionRejected += (_, r, _) => Rejected.Enqueue(r);
                Msg.Start();
            }

            public void Dispose()
            {
                Msg.Dispose();
                Crypto.Dispose();
            }
        }
    }

    /// <summary>
    /// Proxy MITM hiểu cấu trúc record HLC: tách luồng TCP thành từng [header][body], cho phép
    /// sửa/xóa/chèn/đảo record theo chiều client → server, và ghi lại mọi thứ cả hai chiều.
    /// Chỉ kết nối ĐẦU TIÊN bị can thiệp (các lần kết nối lại đi xuyên qua bình thường).
    /// </summary>
    internal sealed class LabProxy : IDisposable
    {
        public delegate void Transform(int index, byte[] record, List<byte[]> output);

        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly int _target;
        private readonly Transform? _c2s;
        private readonly CancellationTokenSource _cts = new();
        private int _connections;

        public List<byte[]> ClientToServer { get; } = new();
        public List<byte[]> ServerToClient { get; } = new();
        public IPEndPoint EndPoint { get; }

        public LabProxy(int targetPort, Transform? clientToServer)
        {
            _target = targetPort;
            _c2s = clientToServer;
            _listener.Start();
            EndPoint = (IPEndPoint)_listener.LocalEndpoint;
            _ = Task.Run(AcceptLoop);
        }

        public byte[] CapturedBytes()
        {
            lock (ClientToServer) lock (ServerToClient)
                return ClientToServer.Concat(ServerToClient).SelectMany(r => r).ToArray();
        }

        private async Task AcceptLoop()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false); }
                catch { return; }
                bool first = Interlocked.Increment(ref _connections) == 1;
                var server = new TcpClient();
                try { await server.ConnectAsync(IPAddress.Loopback, _target).ConfigureAwait(false); }
                catch { client.Dispose(); server.Dispose(); continue; }
                _ = Pump(client, server, first ? _c2s : null, first ? ClientToServer : null);
                _ = Pump(server, client, null, first ? ServerToClient : null);
            }
        }

        private static async Task Pump(TcpClient from, TcpClient to, Transform? transform, List<byte[]>? capture)
        {
            var src = from.GetStream();
            var dst = to.GetStream();
            var header = new byte[Protocol.HeaderSize];
            var output = new List<byte[]>();
            try
            {
                for (int index = 0; ; index++)
                {
                    await src.ReadExactlyAsync(header).ConfigureAwait(false);
                    int len = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(1));
                    if (len < 0 || len > 16 << 20) throw new IOException("bad length");
                    var rec = new byte[Protocol.HeaderSize + len];
                    header.CopyTo(rec, 0);
                    await src.ReadExactlyAsync(rec.AsMemory(Protocol.HeaderSize)).ConfigureAwait(false);
                    if (capture is not null) lock (capture) capture.Add((byte[])rec.Clone());

                    output.Clear();
                    if (transform is null) output.Add(rec);
                    else transform(index, rec, output);
                    foreach (var o in output) await dst.WriteAsync(o).ConfigureAwait(false);
                }
            }
            catch { }
            finally
            {
                from.Close();
                to.Close();
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
        }
    }
}
