# Hyper-LAN Commander

> Secure, zero-configuration LAN communication and file transfer — built from raw sockets up, with end-to-end encryption. WPF / .NET, no third-party networking libraries.

Hyper-LAN Commander lets machines on the same local network automatically discover each other, chat, and exchange files with **AES-256-GCM end-to-end encryption**, **forgery-proof cryptographic identities**, and **resumable downloads** that survive network interruptions.

*Bilingual UI (English / Vietnamese) — switchable at runtime.*

<!-- Add screenshots here:
![Main window](docs/screenshot-main.png)
![Encrypted traffic in Wireshark](docs/wireshark-comparison.png)
-->

## Features

| Feature | Description |
|---|---|
| 🔍 **Zero-configuration discovery** | Peers find each other automatically via a two-way UDP broadcast handshake — no IP entry required |
| 💬 **Concurrent TCP messaging** | One-to-one chat with multiple peers simultaneously; low latency (Nagle disabled) |
| 📁 **Consent-first file transfer** | Not a single data byte is transmitted until the receiver explicitly accepts |
| ⏸ **Resumable downloads** | Interrupted transfers continue from the exact byte offset — no restarting from zero |
| 🔐 **End-to-end encryption** | Every packet is AES-256-GCM ciphertext; session keys are negotiated via ECDH and never travel over the network |
| 🪪 **Cryptographic identity** | Each machine has an unforgeable key fingerprint; key changes at a known IP trigger a security warning (TOFU model, as used by Signal) |
| 🌐 **Bilingual UI** | English ⇄ Vietnamese, hot-switchable, preference persisted across sessions |

## Design Philosophy

**Privacy by consent.** The app only sees machines that *opt in* by running it — there is deliberately no network-wide device scanning. No file lands on disk without an explicit user decision.

**Identity ≠ address.** An IP is just a route, free to change (DHCP renewal, Wi-Fi → Ethernet) without losing the session. True identity is an ECDH P-256 key pair generated on first launch; the 64-bit public-key fingerprint is a "credential" that cannot collide or be forged. If the key at a familiar IP changes, the user gets an explicit security warning instead of silent trust.

**Fail-closed.** A packet tampered with in transit fails GCM authentication, and the connection is terminated immediately rather than silently ignoring the corruption.

## Architecture

```
┌─────────────────────────  MainWindow (WPF)  ─────────────────────────┐
│              UI · consent dialogs · progress · localization           │
└──────┬──────────────────┬──────────────────────┬─────────────────────┘
       │                  │                      │
┌──────▼───────┐  ┌───────▼────────┐  ┌──────────▼──────────┐
│ Discovery    │  │ Messaging      │  │ FileTransfer        │
│ Service      │  │ Service        │◀─┤ Service             │
│ (UDP 8888)   │  │ (TCP 8889)     │  │ (offer/accept/chunk)│
└──────────────┘  └───────┬────────┘  └─────────────────────┘
                          │
                 ┌────────▼────────┐     ┌──────────────────┐
                 │ Protocol        │     │ CryptoService    │
                 │ (binary framing)│     │ (ECDH + AES-GCM) │
                 └─────────────────┘     └──────────────────┘
```

**DiscoveryService** — two-way UDP broadcast handshake: `DISCOVER` (broadcast) is answered with a unicast `REPLY` to the exact sender, so the scanning machine sees responders too. Requests are sent 3× to compensate for UDP's unreliability.

**MessagingService** — multi-peer TCP with a *worker-per-connection* model; a per-connection `SemaphoreSlim` prevents interleaved writes from concurrent threads corrupting the stream.

**Protocol** — length-prefixed binary framing `[4B length][1B type][payload]`, solving TCP's *stream-without-boundaries* nature; partial reads are handled with `ReadExactlyAsync`. New packet types (files, handshake) plug in without touching the framing layer.

**FileTransferService** — 64 KB chunks; resume requires **no metadata file**: the length of the on-disk `.part` file *is* the offset, since TCP's ordering guarantee means the partial file is always a valid prefix.

**CryptoService** — persistent ECDH P-256 identity (stored in `%AppData%\HyperLAN\identity.key`); per-session key = `HKDF(ECDH shared secret, saltA ⊕ saltB)`, giving a fresh key every session even with stable identities.

## File Transfer Protocol (consent-first + resume)

```
Sender                                 Receiver
  │── FileOffer {id, name, size} ──────▶│  (user sees an accept/reject dialog)
  │◀── FileAccept {id, offset} ─────────│  offset = existing .part length → RESUME
  │── FileChunk × N (from offset) ─────▶│  appended to .part
  │── FileComplete ────────────────────▶│  .part atomically renamed to final file
```

Every frame except the public-key handshake is ciphertext: `[12B nonce][ciphertext][16B GCM tag]`.

## Threat Model & Mitigations

| Threat | Mitigation |
|---|---|
| Eavesdropping on LAN traffic | AES-256-GCM encryption; key agreement via ECDH — passive capture yields only noise |
| Packet tampering (MITM modification) | GCM authentication tag; verification failure closes the connection (fail-closed) |
| Path traversal via malicious filenames | Filenames from remote peers are stripped of all path components before touching disk |
| Disk-exhaustion via oversized transfers | Received bytes are capped at the size declared in the accepted offer; frames capped at 16 MB |
| IP takeover / peer impersonation | TOFU fingerprint tracking; identity change at a known IP raises a prominent warning |
| Unsolicited file delivery | Consent-first protocol: zero data bytes before explicit user acceptance |

## Technical Highlights

- **Transport-layer fundamentals in practice**: TCP three-way handshake, flow control, and stream semantics vs. UDP broadcast trade-offs — all handled with raw `Socket`/`TcpClient`/`UdpClient`, no networking frameworks
- **Asynchronous, multi-threaded design**: `async/await` throughout; per-connection worker tasks; UI marshalling via `Dispatcher`; graceful shutdown with `CancellationToken` + `IDisposable`
- **Binary serialization & buffer management**: hand-rolled framing protocol, chunked streaming I/O
- **Applied cryptography**: ECDH key agreement, HKDF key derivation, AES-GCM authenticated encryption, trust-on-first-use identity model
- **WPF**: MVVM-style data binding (`ObservableCollection`), runtime localization via `DynamicResource`

## Getting Started

**Requirements:** Windows 10/11, .NET SDK 8+ (project targets `net10.0-windows`), Visual Studio 2022+ recommended.

```bash
git clone https://github.com/<your-username>/Hyper-LAN-Commander.git
cd Hyper-LAN-Commander/networkApp
dotnet run
```

**Try it with two machines on the same Wi-Fi:** launch the app on both → click *Scan Network* → select a peer → chat, or hit 📎 to send a file. On first launch, allow the Windows Firewall prompt (the app uses UDP 8888 + TCP 8889).

**Resume demo:** send a large file → disconnect Wi-Fi mid-transfer → reconnect → send the same file again. The receiver's dialog reports *"X% already received — the transfer will resume"* and the progress bar jumps straight to where it left off.

## Project Structure

```
networkApp/
├── MainWindow.xaml(.cs)       # UI, consent dialogs, localization wiring
├── Localization.cs            # EN/VI runtime language switching
├── Services/
│   ├── DiscoveryService.cs    # UDP auto-discovery (two-way handshake)
│   ├── MessagingService.cs    # TCP transport + encrypted session handshake
│   ├── FileTransferService.cs # offer/accept/chunk/resume state machine
│   └── CryptoService.cs       # identity, ECDH, AES-256-GCM
└── Networking/
    └── Protocol.cs            # length-prefixed binary framing
```

## Limitations & Roadmap

- TOFU fingerprint memory is currently per-session; persisting a `known_peers.json` store is the next step
- Static identity keys are used for ECDH, so the design does not yet provide full perfect forward secrecy (planned: ephemeral session keys signed by the identity key)
- Planned extensions: remote terminal and remote screen sharing over the same encrypted protocol layer

## License

MIT
