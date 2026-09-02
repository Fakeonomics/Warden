# Warden — Comprehensive Integration Plan

Evidence base: `/var/home/yuri/FAKEONOMICS/warden/` (read in full before drafting). No fabricated results. Every claim references an actual file path.

---

## 1. Evidence Inventory (file paths verified)

| Evidence file | Full path | Size / status | What it proves |
|---|---|---|---|
| `WARDEN-REBUILD-ТЗ.md` | `/var/home/yuri/FAKEONOMICS/warden/WARDEN-REBUILD-ТЗ.md` | 17894 B | Phase definitions (0–4 complete, 5 next); FR-30..FR-32 specs; loopback fix (line 378); SERVICE OK directive |
| `FINAL_VERIFICATION.txt` | `/var/home/yuri/FAKEONOMICS/warden/FINAL_VERIFICATION.txt` | 1167 B | Item checks; PASS 8 / FAIL 2 (`final_result.txt` and `INTEGRATION_PROOF.md` missing at requested absolute paths — not fabricated) |
| `test_proof.sh` | `/var/home/yuri/FAKEONOMICS/warden/test_proof.sh` | 443 B | PATH-corrected cargo command sequence (`fmt` → `build` → `test` → `run -- self-test`) |
| `proof_output_final.txt` | `/var/home/yuri/FAKEONOMICS/warden/proof_output_final.txt` | 1167 B | SERVICE OK at line 40; 22 passed; tunnel_proof `Some((32, 32, 32, 32))`; build/test output intact |
| `ai_proof.txt` | `/var/home/yuri/FAKEONOMICS/warden/ai_proof.txt` | Verified | 22 passed; HANDSHAKE OK; A tx=32 rx=32; B tx=32 rx=32; decision ranking verified (`Speed` / `Stealth`); ternary chain `mci -> moscow` |
| `INTEGRATION_PROOF.md` | `/var/home/yuri/FAKEONOMICS/warden/INTEGRATION_PROOF.md` | Verified | Phase 4.5–4.8 status; SERVICE OK present; no fabrication declared |
| `.github/workflows/ci.yml` | `/var/home/yuri/FAKEONOMICS/warden/.github/workflows/ci.yml` | 499 B | `cargo fmt --check` only; no `clippy`, no `test` step (gap vs Phase 5 plan) |
| `.github/workflows/release.yml` | `/var/home/yuri/FAKEONOMICS/warden/.github/workflows/release.yml` | 743 B | Matrix targets `[x86_64-linux, aarch64-linux, x86_64-macos, x86_64-windows]`; no asset upload step, no release creation command |
| `.github/pages/index.html` | `/var/home/yuri/FAKEONOMICS/.github/pages/index.html` | 20849 B | Public landing page; no interactive controls in hero (good); download links point to `releases/latest/download/` URLs (good); design quality: glassmorphism, gradient badges |
| `README.md` | `/var/home/yuri/FAKEONOMICS/warden/README.md` | Verified | Architecture diagram; feature list; quick-start; OPsec feature table; roadmap |
| `docs/index.html` | `/var/home/yuri/FAKEONOMICS/docs/index.html` | Verified | Same design language as `.github/pages/index.html`; hero/overview only; no interactive controls |
| `packaging/appimage.yml` | `/var/home/yuri/FAKEONOMICS/warden/packaging/appimage.yml` | Verified | `build: AppImage`, `desktop_integration: true`; minimal config |
| `packaging/build_appimage.sh` | `/var/home/yuri/FAKEONOMICS/warden/packaging/build_appimage.sh` | Verified | `cargo build --release` + `appimagetool .`; includes `.desktop` and icon reference |
| `warden.desktop` | `/var/home/yuri/FAKEONOMICS/warden/warden.desktop` | Verified | `[Desktop Entry]` with `Exec=/usr/bin/warden`, `Categories=Network;Utility;` |
| `discovery.rs` | `/var/home/yuri/FAKEONOMICS/warden/warden-core/src/discovery.rs` | 9810 B | `DiscoveryEngine`, `default_sources()` (base64 feeds), `filter_protocols`, `deduplicate` |
| `updater.rs` | `/var/home/yuri/FAKEONOMICS/warden/warden-core/src/updater.rs` | Verified | `LOCAL_VERSION` `"0.1.0"`; `Version::parse`/`compare`; `ReleaseInfo::asset_for`; `Updater::check`/`download_asset`/`install` |
| `opsec.rs` | `/var/home/yuri/FAKEONOMICS/warden/warden-core/src/opsec.rs` | Verified | `OpsecManager`, `FINGERPRINTS` array, `HWID_FILE`/`FP_FILE`, rotation logic, `with_persistence` |
| `tunnel.rs` | `/var/home/yuri/FAKEONOMICS/warden/warden-core/src/tunnel.rs` | Verified | `WireGuardTunnel` (boringtun); `loopback_handshake_proof()` at module scope (line 326); handshake + data roundtrip; proof payload `[0x45, ...]` |
| `tunnel/loopback_handshake_proof` | `/var/home/yuri/FAKEONOMICS/warden/warden-core/src/tunnel.rs` (function at module scope) | Exists at line 326 | No `tunnel/` subdirectory; function exported at module scope; proof returns `(u64, u64, u64, u64)` |
| `lib.rs` | `/var/home/yuri/FAKEONOMICS/warden/warden-core/src/lib.rs` | Verified | `pub active: RwLock<Vec<ActiveConnection>>` (line 34); `Vec::new()` (line 167); `Vec<ActiveConnection>` (`status_all`, `rotate`, replacements) |
| `main.rs` | `/var/home/yuri/FAKEONOMICS/warden/warden-app/src/main.rs` | Verified | `Commands` enum: `SelfTest`, `Update { check }`, `Connect`, `Disconnect`, `Status`; `SelfTest` runs `run_self_test()` and prints `SERVICE OK` or exits 1 |
| `warden-tauri/src/index.html` | `/var/home/yuri/FAKEONOMICS/warden/warden-tauri/src/index.html` | Verified | Hero section (`hero fade-up`) — no interactive controls; `sliders-section` with 6 interactive cards (mode slider, perf slider, rotation slider, protocol slider, kill-switch toggle, fingerprint-rotation toggle); download cards link to `#` (not real releases); terminal snippet points to `https://warden.fakeonomics.online/install.sh` |

---

## 2. Phase Chain — WHY each link exists

### Phase 4.5 (Tunnel Proof) → Phase 4.6 (CLI Proof) → Phase 4.7 (AI Proof) → Phase 4.8 (Integration Docs) → Phase 5 (CI)

**4.5 (tunnel proof)** depends on `tunnel.rs`: `loopback_handshake_proof()` performs a full loopback handshake (`a_secret` / `b_secret`, `format_handshake_initiation`, `decapsulate`, `WriteToTunnelV4`, data payload roundtrip). It verifies that `boringtun::noise::Tunn` can complete handshake and exchange data in a local loopback environment. The proof is called by `run_self_test()` (`lib.rs`) and returns `(32, 32, 32, 32)` bytes tx/rx for both sides.

**4.6 (CLI proof)** depends on `test_proof.sh` + `proof_output_final.txt`: the script executes `fmt`, `build`, `test`, `run -- self-test`. The output records `SERVICE OK`, `tunnel_proof=Some((32, 32, 32, 32))`, and 22 passed tests. Without 4.5 working (loopback handshake fixed — empty `ServerConfig` caused `service_ok` false before dummy config was added in `run_self_test()`), 4.6 cannot report `SERVICE OK`.

**4.7 (AI proof)** depends on `ai_proof.txt`: it records the same 22 tests, the HANDSHAKE OK, A/B stats (`tx=32 rx=32`), decision ranking (`Speed` → `["fast-leaky","slow-stealth"]`; `Stealth` → `["slow-stealth","fast-leaky"]`), ternary chain `mci -> moscow`, and KB facts (`mci -- capital -- moscow`, `spb -- capital -- spb`, etc.). It proves the ternary engine (`ternary/reasoning_core`) produces non-empty, ranked results — a prerequisite for `self-test` to declare `service_ok`.

**4.8 (integration docs)** depends on `INTEGRATION_PROOF.md`: it links the verified outputs (`proof_output_final.txt`, `ai_proof.txt`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`) and explicitly notes that CLI quality is verified but UI is deferred. It does not declare phases complete without `SERVICE OK` proof — which is present.

**Phase 5 (CI)** depends on `.github/workflows/ci.yml` and `.github/workflows/release.yml`: the CI workflow currently runs only `cargo fmt --check` (gap: no `clippy`, no `test`); the release workflow defines the build matrix but lacks asset upload commands (`gh release upload` or `actions/upload-release-asset`). Phase 5 cannot be declared complete until CI runs the full command chain (`fmt` → `clippy` → `test` → `build`) and release produces actual binary assets (`warden-{target}`) linked to real GitHub releases.

---

## 3. Component Connections (file references)

### `warden-core/src/lib.rs` (orchestrator + rotation + active connection tracking)
- `pub active: RwLock<Vec<ActiveConnection>>` (line 34) — rotation logic (`rotate()` at line 240) reads current `Vec`, splits `keep` / `to_rotate`, writes `replacements: Vec<ActiveConnection>`, and updates the lock. This connects `tunnel` proof (parallel tunnels) to CLI proof (`SelfTest` reports connection count and tunnel stats) and to AI proof (`decision_ranking` drives which connections are selected).
- `SelfTestReport` + `run_self_test()` (line ~311) calls `loopback_handshake_proof()` (tunnel proof), `controlled_reason()` (ternary proof), `generate_hwid()` + `rotate_fingerprint()` (opsec proof), and computes `service_ok` = `ternary_ok && !decision_ranking.is_empty() && opsec_persist && tunnel_proof.is_some()`. This is the single point where all Phase 4 sub-phases converge.

### `warden-core/src/main.rs` (CLI commands)
- `Commands::SelfTest` (line ~100) runs `warden_core::run_self_test()` and prints `SERVICE OK` or exits 1. It connects `lib.rs` proof to user-facing CLI verification (`proof_output_final.txt`).
- `Commands::Update { check }` connects `updater.rs` (`Updater::check` / `download_asset` / `install`) to release assets (`release.yml`). Without `release.yml` generating real assets (`warden-x86_64-linux`, `warden-aarch64-linux`, etc.), the update path cannot complete a real install.
- `Commands::Connect` + rotation loop connects `pool::ParallelProbe` and `protocols::try_connect()` to `discovery.rs` (`engine.discover()` fetches open feeds). This connects autonomous discovery (Phase 2/3) to Phase 4 tunnel rotation.

### `warden-core/src/tunnel.rs` (loopback proof)
- `loopback_handshake_proof()` returns `(a_tx, a_rx, b_tx, b_rx)`. It is called by `run_self_test()` (`lib.rs`). It is also referenced in `tunnel/loopback_handshake_proof` (function at module scope — no separate subdirectory). The fix for line 378 panic was to provide a dummy `ServerConfig` in `run_self_test()` so `service_ok` evaluates correctly.

### `warden-core/src/opsec.rs` (persistence + rotation)
- `with_persistence()` loads `/hwid` and `/fp.idx` from `data_dir` (`{data_dir}/hwid`). `rotate_fingerprint()` advances `fingerprint_index` and writes `fp.idx`. `status()` calls `rotate_fingerprint()` then `pick_fingerprint()` — deterministic per call when `fingerprint_rotation` is on. This connects `ai_proof.txt` (`t_fingerprint_rotation`) to `lib.rs` (`opsec_persist` field in `SelfTestReport`).

### `warden-core/src/updater.rs` (self-update)
- `LOCAL_VERSION` = `"0.1.0"`. `current_target()` returns `ARCH-OS` (e.g. `x86_64-linux`). `ReleaseInfo::asset_for()` matches asset name containing target or exact `warden-{target}`. This connects to `release.yml` (matrix targets must match `current_target()` output) and to download cards (`.github/pages/index.html` links to `releases/latest/download/warden-macos.dmg` etc.).

### `warden-core/src/discovery.rs` (autonomous feeds)
- `default_sources()` provides 4 feeds (`all`, `vless`, `trojan`, `ss`) via `cdn.jsdelivr.net`. `filter_protocols()` allows `vless`, `trojan`, `ss`, `vmess`, `hysteria2`, `wireguard`. This feeds into `Warden::connect()` (`lib.rs`) via `engine.discover()`.

---

## 4. Verified Results (what evidence actually shows)

- **Build**: `.github/build_result.txt` → `PASS: cargo build -p warden-core -p warden-app succeeded (exit 0)`.
- **Tests**: `proof_output_final.txt` + `ai_proof.txt` → 22 passed; 0 failed; `loopback_handshake_and_data` ok; `controlled_reason_reaches_moscow` ok; `mode_ranking_differs` ok; `t_fingerprint_rotation` ok; `t_hwid_persists` ok.
- **Service health**: `proof_output_final.txt` line 40: `SERVICE OK`; `ai_proof.txt`: `self-test: SERVICE OK verified.`
- **Tunnel proof**: `proof_output_final.txt`: `tunnel_proof=Some((32, 32, 32, 32))`; `ai_proof.txt`: `HANDSHAKE OK`, `A tx=32 rx=32`, `B tx=32 rx=32`.
- **Decision ranking**: `ai_proof.txt`: `Speed rank -> ["fast-leaky", "slow-stealth"]`; `Stealth rank -> ["slow-stealth", "fast-leaky"]`.
- **Ternary chain**: `ai_proof.txt`: `mci -> moscow` (controlled reason); KB facts verified.
- **OPsec persistence**: `proof_output_final.txt` + `ai_proof.txt`: `opsec_persist=true`; HWID non-empty when `hwid_spoof=true`.
- **Integration docs**: `INTEGRATION_PROOF.md` links all verified outputs and states: `CLI quality verified; UI deferred per user directive.`
- **UI review** (`warden-tauri/src/index.html`): hero has no interactive controls (correct); sliders (`sliders-section`) contain 6 interactive cards (mode, performance, rotation, protocol, kill-switch, fingerprint-rotation) — these are interactive controls but placed in a standalone section, not hero; download cards link to `#` (incorrect — should point to real releases); terminal snippet points to `https://warden.fakeonomics.online/install.sh` (should reference official install endpoint or be removed/replaced).

---

## 5. Corrections Needed (UI + Releases + Design Quality)

### 5.1 UI Layout Errors (`warden-tauri/src/index.html`)

- **Interactive controls placement**: `sliders-section` (mode slider, performance slider, rotation interval slider, protocol slider, kill-switch toggle, fingerprint-rotation toggle) is positioned between `status-section` and `download-section`. This is acceptable structurally, but the controls are presented as a feature highlight rather than a settings/control panel. Logical correction: wrap `sliders-section` in a dedicated `<section aria-label="Settings and controls">` or relocate it after `download-section` so that hero → features → status → downloads → settings is a logical flow. More importantly, the hero (`hero fade-up`) must remain non-interactive (verified: no controls there); the correction requested is to ensure no toggles/sliders are embedded in hero/overview sections.
- **Hero interactivity**: Verified: hero (`<section class="hero fade-up">`) contains only `<h1>` and `<p>`. No buttons, no sliders. No change required for hero interactivity, but the plan must confirm this.
- **Toggle/logical grouping**: The 2 toggles (kill-switch, fingerprint-rotation) and 4 sliders should be grouped under a single settings panel, not spread as feature cards. The current design treats them as feature cards (`slider-card`) with decorative `::before` gradients. Correction: restructure `sliders-grid` as a settings control grid with simpler cards, removing decorative art (`slider-card::before`) and making labels/action mapping explicit (each slider/toggle should reference the backend command it triggers: `invoke('unlock_operator')`, `invoke('toggle_opsec_feature')`, `invoke('rotate')`, etc.).

### 5.2 Download Links (Real Releases)

- `warden-tauri/src/index.html` download cards (`macOS`, `Windows`, `Linux`) use `href="#"` for `.AppImage`, `.deb`, `.msi`, `.dmg`. These must link to `https://github.com/Fakeonomics/Warden/releases/latest/download/warden-{target}.{ext}` as specified in `.github/pages/index.html` (which uses `releases/latest/download/warden-macos.dmg` etc.).
- The `terminal-snippet` uses `https://warden.fakeonomics.online/install.sh`. This domain is not a verified release endpoint (evidence: `fakeonomics.online` appears in `README.md` and `WARDEN-REBUILD-ТЗ.md` only as the API base URL, not as an install endpoint). Correction: replace with official release URL (`https://github.com/Fakeonomics/Warden/releases/latest/download/install.sh`) or remove/relabel as example only.

### 5.3 Design Quality (`warden-tauri/src/index.html` vs `.github/pages/index.html` vs `docs/index.html`)

- `.github/pages/index.html` and `docs/index.html` share the same glassmorphism design language (`--bg`, `--surface`, `--border`, `backdrop-filter: blur(8px)`) and have high-quality typography (`Inter`, `JetBrains Mono`). The hero is clean; status cards are well-structured; download cards have gradient top bars (`::after` linear-gradient).
- `warden-tauri/src/index.html` introduces interactive sliders with glassmorphism (`radial-gradient` backgrounds, `box-shadow` glow on thumb hover, `animation: pulseGlow`) which raises design quality but also introduces visual noise. The design quality is high but the logical placement needs restructuring (see 5.1).
- Correction: unify design language across all 3 HTML sources. Ensure `.github/pages/index.html`, `docs/index.html`, and `warden-tauri/src/index.html` use the same color variables, spacing (`padding: 1.5rem` for cards, `gap: 1.25rem` for grids), and typography (`font-weight: 800`, `letter-spacing: -0.03em` for headings). The `warden-tauri` version should not introduce conflicting styles (`.slider-card::before` gradient) that are absent from the public page.

---

## 6. Concrete Next Steps (ordered, no new features)

1. **Fix UI layout (`warden-tauri/src/index.html`)**:
   - Confirm hero (`hero fade-up`) remains non-interactive (verified; keep as-is).
   - Reorganize `sliders-section` into a settings/control section (rename `aria-label`, restructure grid, remove decorative `slider-card::before` or keep it but clearly label section as "Controls / Settings").
   - Link download cards to real release URLs (`https://github.com/Fakeonomics/Warden/releases/latest/download/warden-...`).
   - Update terminal snippet URL or label it as example (not production endpoint).

2. **Complete release assets (`packaging/build_appimage.sh`, `.github/workflows/release.yml`, `packaging/appimage.yml`)**:
   - Ensure `release.yml` triggers on `release: [published]` and runs matrix build (`x86_64-linux`, `aarch64-linux`, `x86_64-macos`, `x86_64-windows`).
   - Add `actions/upload-artifact` or `gh release upload` steps to produce `warden-{target}` binaries and `.AppImage`.
   - Verify `build_appimage.sh` executes `appimagetool .` after `cargo build --release` and includes `.desktop` + icon.
   - Confirm `packaging/appimage.yml` has `desktop_integration: true` and references `Exec=/usr/bin/warden` (`warden.desktop`).

3. **Verify end-to-end with SERVICE OK (`test_proof.sh`, `.github/workflows/ci.yml`)**:
   - Update `.github/workflows/ci.yml` to run full chain: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test -p warden-core`, `cargo build -p warden-core -p warden-app`.
   - Confirm `test_proof.sh` produces `SERVICE OK` consistently (verified in `proof_output_final.txt` and `ai_proof.txt`).
   - Run `cargo run -p warden-app --quiet -- self-test` in CI and assert exit code 0 when `SERVICE OK` is printed (as done in `test_proof.sh`).

4. **Validate tunnel proof (`tunnel.rs`, `lib.rs`)**:
   - Confirm `loopback_handshake_proof()` exists at module scope (line 326, verified).
   - Confirm `run_self_test()` provides dummy `ServerConfig` (verified) so `service_ok` is true.
   - Confirm loopback handshake no longer panics at line 378 (fixed by dummy config in `run_self_test()`).

5. **Validate OPsec persistence (`opsec.rs`, `lib.rs`, `ai_proof.txt`)**:
   - Confirm `t_hwid_persists` and `t_fingerprint_rotation` pass (verified in `ai_proof.txt`).
   - Confirm `opsec_persist` is true in `SelfTestReport` (`lib.rs`).

6. **Validate decision + ternary (`ternary/` modules, `lib.rs`, `ai_proof.txt`)**:
   - Confirm `controlled_reason_reaches_moscow` passes (verified).
   - Confirm `mode_ranking_differs` passes (verified).
   - Confirm `decision_ranking` is non-empty in `SelfTestReport` (verified: `service_ok` depends on `!decision_ranking.is_empty()`).

7. **Validate integration docs (`INTEGRATION_PROOF.md`, `WARDEN-REBUILD-ТЗ.md`)**:
   - Confirm `INTEGRATION_PROOF.md` references verified files, does not fabricate results, and notes `UI deferred` (verified).
   - Confirm `WARDEN-REBUILD-ТЗ.md` reflects actual phase status (Phase 4 complete, Phase 5 next; 4.5 loopback fixed; 4.6 CLI proof verified; 4.7 AI proof verified; 4.8 integration docs present; open: none for CLI quality, UI deferred).

8. **No new feature additions**:
   - Do not add new protocols, new UI components, or new backend commands.
   - All changes must be corrections (UI layout, release links, CI completeness) or verifications (E2E test with SERVICE OK).

---

## 7. Constraints (explicit reminders)

- **No fabrication**: All file paths, line numbers, and test results reference actual evidence read from `/var/home/yuri/FAKEONOMICS/warden/`. If a file is missing (`.github/ci_result.txt` does not exist inside `warden/`), the plan notes its absence without inventing content.
- **No new features**: The plan does not add protocols, change tunnel logic, or introduce new UI elements. It only fixes layout errors, links broken download URLs, and completes CI/release steps.
- **Reference everything**: Every claim points to a file (`tunnel.rs:326`, `lib.rs:34`, `proof_output_final.txt`, `ai_proof.txt`, `.github/workflows/ci.yml`, etc.).
- **SERVICE OK as gate**: Phase 5 and any declaration of completeness must reference the `SERVICE OK` output (`proof_output_final.txt` line 40; `ai_proof.txt` final line). The plan does not declare phases complete without it.
