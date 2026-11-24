# Hyper-LAN Commander

> A LAN security workbench built on its own end-to-end encrypted protocol: zero-config peer discovery, authenticated messaging and resumable file transfer, plus a **Security Center** that audits the network, watches for ARP spoofing, inspects every packet, and **attacks its own protocol to prove the defenses work**.
>
> WPF / .NET 8. Raw sockets, `System.Security.Cryptography` and Windows IP Helper API. No third-party networking or crypto libraries.

*Bilingual UI (English / Vietnamese), switchable at runtime.*

<!-- Screenshots:
![Security Center – Attack Lab](docs/attack-lab.png)
![Protocol Inspector – eavesdropper view](docs/inspector.png)
-->

---

## What it does

### 🛡 Security Center (the main event)

| Module | What it shows | How it works |
|---|---|---|
| **Attack Lab** | 13 classic attacks run against the app's own protocol, each one **BLOCKED** with measured evidence | Two real nodes on `127.0.0.1` plus a record-aware MITM proxy that tampers, replays, drops, reorders, injects, swaps keys, downgrades, floods and fuzzes |
| **Protocol Inspector** | Every HLC2 record entering or leaving the machine, live: handshake, key derivation, nonce counters, ciphertext | Trace hooks in the transport layer. *Eavesdropper view* shows only what Wireshark would see, plus a live ciphertext entropy meter |
| **LAN Audit** | Hosts, MAC vendors, open services, risk rating with remediation advice | ICMP ping sweep → read the OS **ARP table** (finds hosts that block ping) → TCP connect scan of commonly abused ports → banner grab, HTTP `Server` / Basic-auth-over-HTTP, **TLS certificate checks** (expired, self-signed, TLS 1.0/1.1), **unauthenticated Redis** (`PING → +PONG`), Hyper-LAN peer fingerprinting |
| **Threat Monitor** | Background IDS that raises alerts in a security event log | Polls the ARP table every 4 s: **gateway MAC change** (ARP spoofing), foreign MAC claiming the gateway IP (arpspoof/Bettercap signature), **proxy-ARP / client-isolation detection**, IP↔MAC ownership changes, new devices, gateway/DNS changes (rogue DHCP) |
| **This Device** | Attack surface score (0–100) | Listening TCP/UDP sockets **with owning process** (`GetExtendedTcpTable`), Windows Firewall per profile, network category (Public/Private via `INetworkListManager`), Wi-Fi security (Open/WEP/TKIP/WPA2/WPA3) |
| **Tools** | Ping, traceroute, DNS, **encrypted link test** | Traceroute via incrementing ICMP TTL. Link test measures RTT / RFC 3550 jitter / throughput *through* the AES-GCM channel |
| **Report** | One self-contained HTML report | Device audit + LAN findings + Attack Lab evidence + event log |

All audit features are **non-intrusive**: private and link-local ranges only (default /24, max /22), an explicit "I am authorized" consent box, no credential guessing, no exploit payloads.

### 💬 Secure communication (the platform the security features run on)

| Feature | Detail |
|---|---|
| Zero-config discovery + presence | Announce/Query/Reply/Bye over **directed broadcast on every NIC + multicast + loopback**. Works on multi-homed machines (Hyper-V, VPN, VirtualBox, Wi-Fi + Ethernet) where `255.255.255.255` silently picks a single interface |
| Identity, not address | Peers are keyed by **public-key fingerprint**. IP changes (DHCP, Wi-Fi → Ethernet) don't break sessions or transfers. Multiple addresses are raced with **Happy Eyeballs (RFC 8305)** |
| HLC2 handshake | **ECDHE P-256 + ECDSA P-256 + HKDF-SHA256 + AES-256-GCM**: forward secrecy, mutual authentication, key confirmation, per-direction keys, counter nonces |
| Prioritized multiplexing | Control frames (chat, ping, offers) always jump ahead of bulk file chunks, like HTTP/2 stream priority. Chat latency during a saturating transfer is about **1–2 ms** |
| Consent-first transfers | No data byte moves until the receiver clicks *Accept* |
| Self-healing resume | A link drop mid-transfer → auto-reconnect → offset resync → continue. Typically recovers in **under 2 s**, with no user action |
| End-to-end integrity | **SHA-256** of the whole file is computed while streaming and confirmed by the receiver. `.part` files are bound to the file *version*, so a different file with the same name is never appended |
| TOFU + safety numbers | Persistent `known_peers.json`. Warns when a known name shows up with a new key. Signal-style 30-digit **safety number** for out-of-band verification |
| Liveness | 3 s heartbeat with RTT plus TCP keepalive. Dead peers are detected in about 12 s. Graceful `Bye` makes peers disappear instantly |

---

## Attack Lab results

Measured on one machine (`dotnet run --project tests/HlcTests -- security`). All 13 attacks were blocked in about 15 s:

| Attack | Defense | Evidence |
|---|---|---|
| Passive eavesdropping | AES-256-GCM on every record, packet type inside the ciphertext | 0 plaintext hits; ciphertext entropy ≈ 7.8 bits/byte; only `H` (public Hello) and `S` (sealed) records visible |
| Bit-flip tampering | 128-bit GCM tag, fail-closed | Session terminated (`Tampered`); 0 corrupted messages accepted |
| Replay | Implicit 64-bit counter nonce | Duplicate rejected; 0 duplicates delivered |
| Deletion / reordering | Sequential nonces | Next record fails → detected |
| Forged record injection | No key → no valid tag (2⁻¹²⁸) | Rejected |
| **Active MITM key substitution** | Signed transcript salts the KDF | Both sides `AuthFailed`; 0 user bytes sent |
| Impersonation (hijacked address, same name) | Identity = key fingerprint | `IdentityMismatch`; impostor received nothing |
| Version downgrade | No fallback; version is in the signed transcript | `ProtocolError` |
| 2 GB declared frame (memory DoS) | Length validated before allocation (Hello ≤ 4 KB, record ≤ 4 MB) | Closed in < 10 ms; Δalloc ≈ 50 KB |
| Connection flood + Slowloris | ≤ 16 unauthenticated connections per IP, 64 total, 6 s handshake deadline | 24/40 refused instantly, legit user connected in ~5 ms, idle sockets dropped at 6 s |
| Fuzzing (48 malformed streams) | Defensive parser, per-connection failure | 48/48 closed, service healthy |
| **Forward secrecy** (both long-term keys stolen after recording) | Ephemeral ECDH keys destroyed after the handshake | 8 key-recovery attempts → 0 decryptions (the old v1 static-ECDH design would fall here) |

---

## Architecture

```
┌──────────────────────────────── MainWindow (WPF) ─────────────────────────────────┐
│  Chat · transfer cards · drag&drop          Security Center (6 tabs) · HTML report │
└───────┬──────────────────┬────────────────────────┬───────────────────────────────┘
        │                  │                        │
┌───────▼───────┐ ┌────────▼─────────┐ ┌────────────▼───────────┐ ┌───────────────────┐
│ Discovery     │ │ Messaging        │ │ FileTransfer           │ │ Security/         │
│ UDP 8888      │ │ TCP 8889         │◀┤ consent · resume ·     │ │ LanScanner        │
│ bcast+mcast   │ │ fingerprint-keyed│ │ SHA-256 · resync       │ │ ThreatMonitor     │
│ presence/bye  │ │ priority queues  │ ├────────────────────────┤ │ HostAudit         │
└───────────────┘ │ heartbeat/RTT    │◀┤ LinkTest (RTT/jitter/  │ │ SecurityLab+Proxy │
                  │ Happy Eyeballs   │ │ throughput)            │ │ NetTools          │
                  │ trace hooks ─────┼─┼────────────────────────┼─▶ Protocol Inspector│
                  └────────┬─────────┘ └────────────────────────┘ │ NetNative (iphlp) │
                  ┌────────▼─────────┐  ┌──────────────────────┐  └───────────────────┘
                  │ SecureChannel    │  │ CryptoService        │  TrustStore (TOFU)
                  │ HLC2 handshake,  │  │ ECDSA identity, DPAPI│  AppProfile (multi-
                  │ CipherState      │  │ safety numbers       │  instance on 1 PC)
                  └──────────────────┘  └──────────────────────┘
```

### HLC2 wire format

```
Record:  [1B type 'H'|'S'][4B LE length][body]
Hello:   JSON { P:"HLC", V:2, Id:<ECDSA SPKI>, Eph:<ECDH SPKI>, Nonce:<32B>, Name, Port, Instance }   (plaintext)
Sealed:  AES-256-GCM( [1B inner type][payload] ) ‖ 16B tag     nonce = 0⁴ ‖ counter⁸, AAD = 5-byte header
```

### Handshake (SIGMA / TLS 1.3 style, 1-RTT, both sides send at once)

```
A ── Hello{IdA, EphA, NonceA} ──▶ B        th  = SHA-256(helloInitiator ‖ helloResponder)
A ◀── Hello{IdB, EphB, NonceB} ── B        Z   = ECDH(EphA, EphB)      (ephemeral keys destroyed right after)
                                           k_i2r, k_r2i = HKDF-SHA256(salt = th, Z)
A ── Sealed{Auth: SigA(th‖'I')} ──▶ B      B verifies with IdA → it really is A
A ◀── Sealed{Auth: SigB(th‖'R')} ── B      A verifies with IdB → it really is B
```

### File transfer

```
Sender                                     Receiver
  ── FileOffer {id, name, size, versionKey} ─▶  Accept / Decline card
  ◀─ FileAccept {id, offset} ─────────────────  offset = length of the version-bound .part
  ── FileChunk {id, offset, data} × N ───────▶  written only if offset == bytes held (idempotent)
  ◀─ FileAccept {id, held}   (resync) ────────  on gap / reconnect: "rewind to here"
  ── FileComplete {id, SHA-256} ─────────────▶  compare hash → rename .part
  ◀─ FileResult {id, OK | mismatch} ──────────  sender shows "Delivered ✓ verified"
```

---

## Threat model

| Threat | Mitigation |
|---|---|
| Eavesdropping on shared Wi-Fi | AES-256-GCM. Packet types hidden. Only record size and timing are visible |
| Tampering / replay / reorder / deletion | GCM tag + implicit counter nonce + header as AAD → fail-closed |
| Active MITM during key exchange | Ephemeral ECDH authenticated by ECDSA signatures over the full transcript |
| ARP / DNS spoofing redirecting a known peer | Fingerprint check after the handshake (`IdentityMismatch`), plus the ARP monitor alerts |
| Compromise of long-term keys later | Forward secrecy (ECDHE). Identity key wrapped with Windows **DPAPI** at rest |
| Key change at a known name | Persistent TOFU store + warning + safety-number verification |
| Path traversal / DOS device names in file names | Strip all path components, invalid characters, `CON`/`NUL`/`COMx`… |
| Disk exhaustion | Writes capped at the accepted size; free-space check before accepting |
| Memory DoS, flood, slowloris | Length checked before allocation; per-IP pending cap; handshake deadline |
| Unsolicited files | Consent-first: zero data bytes before *Accept* |

---

## Getting started

**Requirements:** Windows 10/11 and the .NET SDK 8 or newer. The project targets `net8.0-windows` (LTS) and rolls forward to newer runtimes.

```bash
git clone https://github.com/<your-username>/Hyper-LAN-Commander.git
cd Hyper-LAN-Commander/networkApp
dotnet run
```

On first launch, allow the Windows Firewall prompt (UDP 8888 + TCP 8889).

**Try it on one PC:** start the app twice. The second window automatically uses its own profile, identity and port, and the two discover each other within a second.

**Resume demo:** send a large file, toggle Wi-Fi mid-transfer, and watch the card go *Paused → Transferring* by itself.

**Security demo:** open **Security → Attack Lab → Run all attacks**, then **Protocol Inspector**, tick *Eavesdropper view*, and send a chat message.

Optional environment variables: `HLC_PROFILE` (force a profile), `HLC_PORT` (TCP port), `HLC_NAME` (display name).

### Tests

```bash
dotnet run --project tests/HlcTests              # 17 protocol/transfer integration tests (real sockets)
dotnet run --project tests/HlcTests -- security  # Attack Lab, host audit, ARP table, link test
```

These cover the handshake, simultaneous-connect tie-break, garbage/slowloris clients, a 96 MB transfer with SHA-256, chat latency under load, connection kill mid-transfer, version-bound `.part` files, cancel/resume, decline, a tampering proxy, graceful shutdown, discovery, legacy key migration and file-name sanitization.

---

## Project structure

```
networkApp/
├── MainWindow.xaml(.cs)          # chat UI + orchestration
├── UI/
│   ├── SecurityCenterView.xaml   # Security Center (6 tabs)
│   ├── ViewModels.cs             # peers, chat, transfer cards
│   └── SecurityViewModels.cs     # audit / inspector / lab rows, converters
├── Networking/
│   ├── Protocol.cs               # record framing, packet types
│   └── SecureChannel.cs          # HLC2 handshake, CipherState (AES-GCM + counter nonce)
├── Services/
│   ├── MessagingService.cs       # sessions, priority writer, heartbeat, Happy Eyeballs, tracing
│   ├── DiscoveryService.cs       # multi-NIC broadcast + multicast presence
│   ├── FileTransferService.cs    # consent, resume, resync, SHA-256
│   ├── CryptoService.cs          # ECDSA identity, DPAPI, safety numbers
│   ├── TrustStore.cs             # persistent TOFU
│   └── AppProfile.cs             # per-instance data dirs / ports
└── Security/
    ├── SecurityLab.cs            # Attack Lab + record-aware MITM proxy
    ├── LanScanner.cs             # sweep → ARP → port scan → service probes
    ├── ThreatMonitor.cs          # ARP spoofing / proxy-ARP / rogue DHCP detection
    ├── HostAudit.cs              # listeners + firewall + network category + Wi-Fi
    ├── NetTools.cs               # ping, traceroute, DNS, encrypted link test
    ├── NetNative.cs              # iphlpapi P/Invoke (ARP table, socket owners)
    ├── Knowledge.cs              # port risk catalogue, OUI vendors
    ├── SecurityLog.cs            # event log (SIEM-style)
    └── ReportExporter.cs         # HTML report
tests/HlcTests/                   # integration + security test runner
```

## Limitations and roadmap

- Record sizes and timing are visible to an observer (no padding or traffic shaping yet).
- The ARP monitor needs one clean baseline. Poisoning that is already active when the app starts can only be flagged as ambiguous.
- On Windows 11 24H2 or newer, reading the Wi-Fi security mode needs Location permission (the app explains how to enable it).
- Discovery cannot cross Wi-Fi client isolation. The Threat Monitor detects and explains this case.
- Roadmap: SMBv1 / weak-cipher TLS probing, PCAP export from the Inspector, ARP-spoof active verification, remote shell over HLC2.

## License

MIT
