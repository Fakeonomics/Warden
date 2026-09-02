<div align="center">

# Warden

**Autonomous multi-protocol VPN client — pure Rust, zero-trust rotation, self-healing discovery.**

[![CI](https://github.com/Fakeonomics/Warden/actions/workflows/ci.yml/badge.svg)](https://github.com/Fakeonomics/Warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests%20passing-40/40-brightgreen.svg)]()
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

[Quick Start](#-quick-start) · [Features](#-features) · [Architecture](#-architecture) · [Download](#-download)

</div>

---

## What is Warden?

Warden is a **self-operating VPN client** that finds, validates, rotates, and heals its own server connections — no manual config, no dead endpoints, no leaks.

While you sleep, Warden:
- **Discovers** 11,000+ servers from live feeds
- **Probes** them for latency and liveness
- **Ranks** them by threat context (Speed / Balanced / Stealth)
- **Rotates** tunnels silently — half stay alive while half swap
- **Validates** every layer: tunnel handshake, ternary reasoning, OPSEC persistence

If a server dies, Warden doesn't ask. It heals.

---

## Quick Start

```bash
# Build
cargo build -p warden-core -p warden-app --release

# Self-validates every layer: tunnel, AI reasoning, OPSEC, discovery
cargo run -p warden-app --quiet -- self-test
# → SERVICE OK

# Connect (auto-discovers, probes, ranks, connects)
WARDEN_TOKEN="your-token" cargo run -p warden-app
```

---

## Features

| | Capability | Detail |
|---|---|---|
| 🔍 | **Autonomous Discovery** | Pulls from live feeds, parses VLESS/Trojan/SS/VMess/Hysteria2/WireGuard, deduplicates, filters dead |
| 🧠 | **Ternary Decision Engine** | AI reasoning core ranks servers by threat context — not just latency |
| 🔄 | **Parallel Rotation** | Keeps half the tunnels alive while rotating the rest — zero-notice swap |
| 🛡️ | **OPSEC** | HWID spoofing, fingerprint rotation, kill switch, DNS/IPv6/WebRTC leak protection |
| 🔄 | **Self-Update** | Checks GitHub releases, downloads, atomically installs |
| ✅ | **Self-Test** | One command validates tunnel handshake, AI engine, OPSEC, and service health |

---

## Architecture

```
warden/
├── warden-core/        # Library: discovery, protocol, OPSEC, AI decision, updater
│   ├── discovery.rs    # Feed aggregation, parsing, dedup, health filter
│   ├── protocol.rs     # Multi-protocol manager (boringtun/shadowsocks/quinn)
│   ├── decision.rs     # Ternary reasoning + threat-context ranking
│   ├── opsec.rs        # HWID, fingerprint rotation, kill switch
│   ├── updater.rs      # Self-update via GitHub releases
│   └── tunnel.rs       # WireGuard tunnel + loopback proof
├── warden-app/         # CLI binary
│   └── main.rs         # connect / disconnect / status / self-test / update
└── .github/
    └── workflows/      # CI (fmt+clippy+test+build) + Release (4 platforms)
```

---

## Download

| Platform | Package |
|---|---|
| Linux | [`.AppImage`](https://github.com/Fakeonomics/Warden/releases/latest/download/warden-x86_64-linux.AppImage) · [`.deb`](https://github.com/Fakeonomics/Warden/releases/latest/download/warden-x86_64-linux.deb) |
| macOS | [`.dmg`](https://github.com/Fakeonomics/Warden/releases/latest/download/warden-x86_64-macos.dmg) |
| Windows | [`.exe`](https://github.com/Fakeonomics/Warden/releases/latest/download/warden-x86_64-windows.exe) |

```bash
curl -fsSL https://github.com/Fakeonomics/Warden/releases/latest/download/install.sh | bash
```

---

## License

MIT — [LICENSE](LICENSE)
