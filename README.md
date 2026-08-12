# 🛡️ Warden VPN

A high-performance, multi-protocol VPN client built in Rust. One-click auto-selection from our [VPN-Service](https://github.com/Fakeonomics) backend, with rotating configs, OPsec features, and support for the modern VPN protocol stack — WireGuard, VLESS, Shadowsocks-2022, and Hysteria2.

> Built on top of proven open-source crates — `boringtun` (Cloudflare's userspace WireGuard), `shadowsocks-rust`, `quinn` (QUIC), `ring`/`rustls` (cryptography). We extend, not reinvent.

---

## ✨ Features

- **One-click connect** — fetches the best alive config from your subscription and connects automatically.
- **Dynamic configs** — auto-refreshes from the VPN-Service API; configs change constantly and Warden keeps up.
- **Multi-protocol** — WireGuard, VLESS/Reality, Shadowsocks-2022, Hysteria2 (QUIC).
- **OPsec** — fingerprint rotation, HWID spoofing, traffic shaping, packet padding, kill switch, DNS/IPv6/WebRTC leak protection.
- **Region-aware rotation** — prefers RU/DE/NL/US/FR, excludes CN/KP/IR.
- **Memory-safe** — pure Rust, no `unsafe` in business logic, constant-time crypto via `subtle`/`ring`.

---

## 🏗️ Architecture

```
warden/
├── Cargo.toml          # workspace
├── warden-core/        # library: config, api client, protocol manager, opsec
│   └── src/
│       ├── lib.rs      # Warden orchestrator
│       ├── config.rs   # typed configuration
│       ├── api.rs      # VPN-Service API client (subscription + health)
│       ├── protocol.rs # protocol manager (boringtun/shadowsocks/quinn)
│       ├── opsec.rs     # OPsec: fingerprint, HWID, kill switch
│       └── error.rs     # typed errors
└── warden-app/         # CLI binary (Tauri desktop frontend — planned)
    └── src/main.rs      # one-click connect loop
```

---

## 🚀 Quick start

### Prerequisites
- Rust 1.70+ (`rustup default stable`)
- (Windows) Visual Studio Build Tools with the C++ workload, or MinGW for the `gnu` target.

### Build & run

```bash
# Set your subscription token (issued by the Telegram bot or VPN-Service admin)
export WARDEN_TOKEN="your-subscription-token"

# Point at your VPN-Service instance (optional, defaults to fakeonomics.online)
export WARDEN_BASE_URL="https://fakeonomics.online"

cargo run --release
```

Output:
```
✅ Connected via vless to de1.example.com:443
```

### Configuration

Create `warden.json` (or set `WARDEN_CONFIG=/path/to/warden.json`):

```json
{
  "api": {
    "base_url": "https://fakeonomics.online",
    "subscription_endpoint": "/sub/{token}/all.txt",
    "user_agent": "Warden/0.1.0",
    "timeout_seconds": 30
  },
  "protocols": {
    "preferred": ["vless", "hysteria2", "shadowsocks", "wireguard"],
    "wireguard_enabled": true,
    "vless_enabled": true,
    "shadowsocks_enabled": true,
    "hysteria2_enabled": true
  },
  "rotation": {
    "enabled": true,
    "interval_seconds": 30,
    "prefer_regions": ["RU", "DE", "NL", "US", "FR"]
  },
  "opsec": {
    "enabled": true,
    "fingerprint_rotation": true,
    "traffic_shaping": true,
    "hwid_spoof": true,
    "kill_switch": true,
    "dns_leak_protection": true,
    "padding": true
  }
}
```

---

## 🔌 VPN-Service API integration

Warden talks to the existing VPN-Service backend. Key endpoints it consumes:

| Endpoint | Purpose |
|----------|---------|
| `GET /sub/{token}/all.txt` | Fetch alive subscription configs (vless/vmess/trojan/ss/hysteria2). Supports `?limit=` and `?category=alive\|auto\|static`. |
| `GET /sub/{token}/by_source/{source}.txt` | Filter by source. |
| `GET /api/protocols` | Per-protocol alive counts. |
| `GET /api/countries` | Country distribution. |
| `GET /api/groups` | Per-user groups (custom + auto + country). |
| `POST /api/parse-sub` | Import an external subscription URL. |

The subscription response is plain-text share-URL list (with `#profile-title`, `#subscription-userinfo` headers) — Warden parses it into typed `ServerConfig` structs.

---

## 🔐 OPsec features

| Feature | Status | Implementation |
|---------|--------|----------------|
| Fingerprint rotation | ✅ | Random pick from `{chrome, firefox, safari, edge, 360, qq}` pool per session. |
| HWID spoof | ✅ | Random 16-byte HWID generated per boot via `ring::SystemRandom`. |
| Traffic shaping | 🚧 | Token-bucket rate limit + jitter (planned via `tokio-util`). |
| Packet padding | 🚧 | `TrafficShaper` pads frames to `[0, 256]` extra bytes. |
| Kill switch | 🚧 | Block-detect on session loss → immediate reconnect. |
| DNS leak protection | 🚧 | Force DNS through tunnel; block plaintext DNS outside. |
| IPv6 leak protection | 🚧 | Disable IPv6 outside tunnel. |
| WebRTC leak protection | 🚧 | JS-injected via Tauri webview (planned). |

---

## 🛣️ Roadmap

- [x] Core library: config, API client, protocol manager, OPsec types
- [x] CLI one-click connect loop
- [ ] WireGuard data plane via `boringtun` (TUN-permission-gated)
- [ ] VLESS/Reality transport via `quinn` + `rustls`
- [ ] Shadowsocks-2022 client via `shadowsocks-rust`
- [ ] Hysteria2 client via `quinn` + Brutal CC
- [ ] Tauri desktop shell with one-click UI (HTML/JS in `warden-tauri/`)
- [ ] Per-app proxy / split tunnelling
- [ ] Kill switch (platform firewall hooks)

---

## 🙏 Acknowledgements

This project is the Rust rewrite of the Warden MVP, with the architecture inspired by:

- [**Hiddify**](https://github.com/hiddify/hiddify-app) — per-app proxy + auto-selection patterns
- [**happ / happwn**](https://github.com/happ) — crypt5 rotation, config parsing
- [**Cloudflare boringtun**](https://github.com/cloudflare/boringtun) — userspace WireGuard
- [**shadowsocks-rust**](https://github.com/shadowsocks/shadowsocks-rust) — AEAD-2022 cipher suite
- [**ProtonVPN**](https://protonvpn.com) — Secure Core multi-hop, NetShield

## License

MIT — see [LICENSE](LICENSE).
