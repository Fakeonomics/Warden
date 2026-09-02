# PROJECT_MEMORY.md — Warden Rebuild Log

## Phases
| Phase | Topic | Status | Deliverables |
|---|---|---|---|
| Phase 0 | Workspace scaffolding + core types | Done | `Cargo.toml` workspace, `warden-core`, `warden-app` |
| Phase 1 | Config + API client | Done | `config.rs`, `api.rs` |
| Phase 2 | Protocol manager (boringtun/shadowsocks/quinn) | Done | `protocol.rs` |
| Phase 3 | Ternary decision + pool scoring | Done | `ternary/`, `pool.rs`, `decision.rs` |
| **Phase 4** | **OPSEC hardening + self-update (foreground)** | **Complete** | `updater.rs`, `opsec.rs` persistence, `main.rs::Commands::Update` |
| Phase 5 | CI / GitHub Actions | Next | `.github/workflows/*.yml` |

## Phase 4 — Complete
Date completed: 2026-08-31

### Summary
Implemented self-update and OPSEC persistence as foreground operations:

- **`warden-core/src/updater.rs`**: semver-lite (manual `Version` parse + compare, no semver crate), `local_version()`, `current_target()`, `Asset`/`ReleaseInfo`/`Updater`/`UpdateCheck` types, GitHub API `check()`, `download_asset()`, `install()` via temp-file + rename over `current_exe`. Uses `reqwest` 0.12 (already a workspace dep) with `rustls-tls`.
- **`warden-core/src/opsec.rs`**: `OpsecManager` hardened with persistence fields (`hwid`, `hwid_file`, `fingerprint_index`, `fp_file`). `with_mode` delegates to `with_persistence(...,None)`; `Warden::new` calls `with_persistence(...,Some(data_dir))`. HWID generated via `ring::SystemRandom` (16 bytes, base64 URL_SAFE_NO_PAD) and persisted to `{data_dir}/hwid`. `generate_hwid()` returns empty when `hwid_spoof` is off. Fingerprint rotation cycle stored at `{data_dir}/fp.idx` (u8); `status()` advances then picks; `rotate_fingerprint()` wraps and persists.
- **`warden-core/src/error.rs`**: Added `Update(String)` and `Download(String)` variants.
- **`warden-core/src/lib.rs`**: `pub mod updater` + re-exports.
- **`warden-app/src/main.rs`**: `Commands::Update { check }` — builds reqwest client w/ UA, creates `Updater`, checks GitHub latest release, prints up-to-date vs update available; when `!check`, downloads asset for target and installs via temp-rename.

### Verification
- `cargo fmt` — applied (clean)
- `cargo build -p warden-core -p warden-app` — ✅ success
- `cargo test -p warden-core` — ✅ 22 passed, 0 failed

### Constraints honoured
- No new Cargo.toml dependencies.
- No `unsafe` in business logic.
- Existing public API preserved (`OpsecStatus`, `current_hwid` as `String`, `OpsecManager::with_mode`, `Warden::connect` flow, `TernaryDecisionHook`, `reasoning_core::new(256)`, etc.).
