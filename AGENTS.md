# AGENTS.md — Warden (Rust workspace)

## Project layout
- **Workspace root**: `/var/home/yuri/FAKEONOMICS/warden/Cargo.toml`
- **warden-core** — library crate (config, api, protocol manager, opsec, updater, ternary decision)
- **warden-app** — CLI binary (clap-based)
- **warden-tauri** — Tauri desktop shell (excluded from workspace `default-members`)

## Build / test commands
| Command | Purpose |
|---|---|
| `cargo fmt --check` | Verify formatting |
| `cargo fmt` | Apply formatting fixes |
| `cargo build -p warden-core -p warden-app` | Build core library + CLI |
| `cargo test -p warden-core` | Run core library unit tests |
| `cargo clippy -p warden-core -p warden-app -- -D warnings` | Lint (may have minor warnings in optional tauri crate) |

## Notes
- Rust 1.70+, edition 2021, no `unsafe` in business logic.
- No new dependencies may be added without workspace-level review (Cargo.toml workspace.dependencies).
- `gh` CLI is not required; updater uses `reqwest` + raw GitHub API HTTP.
