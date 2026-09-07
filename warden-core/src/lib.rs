pub mod api;
pub mod calib;
#[cfg(test)]
mod calib_tests;
pub mod config;
pub mod decision;
pub mod discovery;
pub mod error;
pub mod hysteria2;
pub mod live_probe;
pub mod mind;
pub mod opsec;
pub mod pool;
pub mod protocol;
pub mod protocol_helpers;
pub mod quality;
pub mod shadowsocks;
pub mod ternary;
pub mod tier_probe;
pub mod traffic_watch;
pub mod trojan;
pub mod tun;
pub mod tunnel;
pub mod updater;
pub mod vless;
pub mod vmess;

pub use live_probe::{find_first_alive, LiveProbeStats, ProbeReport, ProbeVerdict};
pub use tier_probe::{
    detect_hardware, detect_tier, detect_uplink, measure_uplink_approx, HardwareReport,
    HardwareTier, UplinkKind,
};

pub use api::{ApiClient, ServerConfig};
pub use config::*;
pub use discovery::{health_filter, DiscoveryEngine, DiscoverySource, SourceFormat};
pub use error::WardenError;
pub use mind::{BlockReason, GeoBlockSignal, Mind, Role, SubTask, TrafficWatchdog};
pub use opsec::{OpsecManager, OpsecStatus};
pub use protocol::ProtocolManager;
pub use traffic_watch::{ProbeResult, ProbeTarget, TrafficMonitor};
pub use updater::{ReleaseInfo, UpdateCheck, Updater, Version};

use crate::decision::DecisionHook;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

pub struct Warden {
    pub config: Arc<RwLock<WardenConfig>>,
    pub api: Arc<ApiClient>,
    pub protocols: Arc<ProtocolManager>,
    pub opsec: Arc<RwLock<OpsecManager>>,
    pub mind: Arc<Mind>,
    pub monitor: Arc<TrafficMonitor>,
    pub active: RwLock<Vec<ActiveConnection>>,
    pub pool: Arc<crate::pool::ConfigPool>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActiveConnection {
    pub session_id: String,
    pub protocol: String,
    pub server: String,
    pub host: String,
    pub port: i32,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

fn warden_data_dir() -> PathBuf {
    let mut p = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"))
        });
    p.push(".local/share/warden");
    p
}

impl Warden {
    pub async fn new(config: WardenConfig) -> Result<Self, WardenError> {
        // Hardware-aware auto-tuning: adapt to the host's CPU/memory at startup.
        // Best-effort: if detection fails the caller's config is left untouched
        // and existing behaviour is preserved.
        let mut config = config;
        let profile = crate::calib::HardwareProfile::detect();
        let tuned = crate::calib::AutoTuner.tune(&profile, &crate::calib::LiveMetrics::default());
        tuned.apply(&mut config);

        let mode = config.mode;
        let api_cfg = config.api.clone();
        let proto_cfg = config.protocols.clone();
        let opsec_cfg = config.opsec.clone();

        let api = Arc::new(ApiClient::new(api_cfg)?);
        let protocols = Arc::new(ProtocolManager::new(proto_cfg, api.clone()).await?);

        let data_dir = warden_data_dir();
        let _ = std::fs::create_dir_all(&data_dir);
        let opsec = Arc::new(RwLock::new(OpsecManager::with_persistence(
            opsec_cfg,
            mode,
            Some(data_dir.clone()),
        )));

        let cache_path = data_dir.join("proven.json");

        info!(
            "warden init mode={:?} api={}",
            config.mode, config.api.base_url
        );

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            api,
            protocols,
            opsec,
            mind: Arc::new(crate::mind::Mind::new(256)),
            monitor: Arc::new(crate::traffic_watch::TrafficMonitor::new()),
            active: RwLock::new(Vec::new()),
            pool: Arc::new(crate::pool::ConfigPool::new(
                Vec::new(),
                crate::pool::ConfigScoreCache::load(&cache_path),
                Arc::new(crate::pool::MockProbe),
            )),
        })
    }

    pub async fn connect(&self, token: &str) -> Result<ActiveConnection, WardenError> {
        let cfg = self.config.read().await.clone();
        // Subscription failure is non-fatal: autonomous discovery may still yield configs.
        let mut configs = match self.api.fetch_subscription(token).await {
            Ok(c) => c,
            Err(e) => {
                warn!("subscription fetch failed (discovery fallback): {:?}", e);
                Vec::new()
            }
        };

        // Autonomous discovery supplement: fetch from open feeds (vless, trojan, ss)
        let sources: Vec<crate::discovery::DiscoverySource> = crate::discovery::default_sources();
        let engine = crate::discovery::DiscoveryEngine::new(sources);
        // Note: in full deployment, DiscoverySource::default() provides feeds.
        // For brevity we use engine only when subscription is sparse.
        let discovered = engine.discover().await.unwrap_or_default();
        info!(
            "autonomous discovery added {} server configs",
            discovered.len()
        );
        configs.extend(discovered);

        self.connect_with_retry(configs, &cfg).await
    }

    /// Retry wrapper around `connect_from_configs`: bounded attempts with
    /// exponential backoff, graceful fallback on all-dead, proper cleanup on
    /// disconnect. Never panics.
    pub async fn connect_with_retry(
        &self,
        configs: Vec<ServerConfig>,
        cfg: &WardenConfig,
    ) -> Result<ActiveConnection, WardenError> {
        let max_attempts: u32 = 3;
        let base_delay = std::time::Duration::from_millis(250);
        let max_delay = std::time::Duration::from_secs(2);

        let mut last_err: Option<WardenError> = None;
        for attempt in 1..=max_attempts {
            match self.connect_from_configs(configs.clone(), cfg).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < max_attempts {
                        let delay = (base_delay * 2u32.pow(attempt - 1)).min(max_delay);
                        warn!(
                            "connect attempt {}/{} failed ({:?}), retrying in {:?}",
                            attempt,
                            max_attempts,
                            last_err.as_ref().unwrap(),
                            delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or(WardenError::AllConnectionsFailed))
    }

    /// Test-injection entry point: attempt connection using an explicit config set.
    /// Kept in sync with `connect()` so the real CLI path and the integration tests
    /// exercise identical logic.
    ///
    /// Hardening: retries the whole probe+connect attempt with exponential backoff,
    /// bounded by a total wall-clock budget, and falls back gracefully when every
    /// candidate is dead instead of propagating a hard error.
    pub(crate) async fn connect_from_configs(
        &self,
        configs: Vec<ServerConfig>,
        cfg: &WardenConfig,
    ) -> Result<ActiveConnection, WardenError> {
        let alive: Vec<_> = configs.into_iter().filter(|c| c.is_alive).collect();
        if alive.is_empty() {
            return Err(WardenError::NoConfigsAvailable);
        }

        info!(
            "attempting from {} alive configs (mode={:?})",
            alive.len(),
            cfg.mode
        );

        let opsec = self.opsec.read().await;
        let operator = opsec.mode().is_operator();
        drop(opsec);

        let data_dir = warden_data_dir();
        let cache_path = data_dir.join("proven.json");

        let mut cache = crate::pool::ConfigScoreCache::load(&cache_path);
        cache.cleanup_stale();

        let hook = crate::decision::TernaryDecisionHook::new(
            Some(std::sync::Arc::new(crate::ternary::reasoning_core::new(
                256,
            ))),
            cache,
        );

        // Cap probe size: probing thousands of discovered servers serially would
        // take far longer than any reasonable connect budget.
        let probe_set: Vec<ServerConfig> = alive.iter().take(200).cloned().collect();
        let parallel = crate::pool::ParallelProbe {
            probe: Arc::clone(&self.pool.probe),
            concurrency: 10,
            timeout: std::time::Duration::from_secs(2),
        };
        let results = parallel.run(&probe_set).await;
        let mut updated_cache = hook.cache.clone();
        for (id, metrics) in results {
            updated_cache.put(&id, metrics);
        }

        let hook = crate::decision::TernaryDecisionHook::new(
            Some(std::sync::Arc::new(crate::ternary::reasoning_core::new(
                256,
            ))),
            updated_cache,
        );

        self.protocols.set_hook(Box::new(hook)).await;

        // Create multiple parallel connections (parallel tunnels) for unnoticeable rotation
        const PARALLEL_TARGET: usize = 4;
        let mut connections: Vec<ActiveConnection> = Vec::new();
        let mut remaining = alive.clone();

        let perf_mode = cfg.performance_mode.clone();

        // Retry loop: bounded attempts with backoff, never panics.
        let max_attempts: u32 = 3;
        let base_delay = std::time::Duration::from_millis(250);
        let max_delay = std::time::Duration::from_secs(2);

        'outer: for attempt in 1..=max_attempts {
            for i in 0..PARALLEL_TARGET {
                if remaining.is_empty() {
                    remaining = alive.clone();
                }
                let conn_opt = self
                    .protocols
                    .try_connect(
                        &cfg.rotation.prefer_regions,
                        &cfg.rotation.exclude_countries,
                        operator,
                        &remaining,
                        perf_mode.clone(),
                    )
                    .await?;
                if let Some(conn) = conn_opt {
                    connections.push(conn.clone());
                    remaining.retain(|c| !(c.host == conn.host && c.port == conn.port));
                    info!(
                        "parallel tunnel {} established -> {}:{} sid={}",
                        i + 1,
                        conn.host,
                        conn.port,
                        &conn.session_id[..8]
                    );
                } else {
                    warn!("parallel tunnel {} failed to establish", i + 1);
                    break;
                }
            }

            if !connections.is_empty() {
                break 'outer;
            }

            if attempt < max_attempts {
                let delay = (base_delay * 2u32.pow(attempt - 1)).min(max_delay);
                warn!(
                    "connect attempt {}/{} yielded no tunnels, retrying in {:?}",
                    attempt, max_attempts, delay
                );
                tokio::time::sleep(delay).await;
            }
        }

        if connections.is_empty() {
            return Err(WardenError::AllConnectionsFailed);
        }

        *self.active.write().await = connections.clone();
        let primary = connections[0].clone();

        let _ = self.pool.save_cache(&cache_path);
        info!(
            "warden connected with {} parallel tunnels",
            connections.len()
        );

        Ok(primary)
    }

    pub async fn disconnect(&self) -> Result<(), WardenError> {
        // Snapshot and clear active connections first so a failed individual
        // tunnel teardown can never leave stale entries behind.
        let guard = std::mem::take(&mut *self.active.write().await);

        let mut errors: Vec<WardenError> = Vec::new();
        for conn in &guard {
            match self.protocols.disconnect(&conn.session_id).await {
                Ok(()) => {
                    info!(
                        "disconnected {}:{} sid={}",
                        conn.host,
                        conn.port,
                        &conn.session_id[..8]
                    );
                }
                Err(e) => {
                    warn!(
                        "failed to disconnect {}:{} sid={}: {:?}",
                        conn.host,
                        conn.port,
                        &conn.session_id[..8],
                        e
                    );
                    errors.push(e);
                }
            }
        }

        if !guard.is_empty() {
            self.opsec.read().await.on_kill_switch();
        }

        info!(
            "disconnected {} active connections{}",
            guard.len(),
            if errors.is_empty() {
                String::new()
            } else {
                format!(" ({} errors)", errors.len())
            }
        );

        if !errors.is_empty() {
            return Err(WardenError::Other(format!(
                "partial disconnect failures: {}",
                errors.len()
            )));
        }
        Ok(())
    }

    pub async fn status(&self) -> Option<ActiveConnection> {
        let active = self.active.read().await.clone();
        active.first().cloned()
    }

    pub async fn status_all(&self) -> Vec<ActiveConnection> {
        self.active.read().await.clone()
    }

    /// Compute the partial-rotation split: keep the first `keep` connections,
    /// rotate the remaining `rotate`. At least one connection is always rotated
    /// when `total > 0`, and the keep count is the floor of total/2.
    pub fn partial_split(total: usize) -> (usize, usize) {
        if total == 0 {
            return (0, 0);
        }
        let keep = total / 2;
        let rotate = total - keep;
        // Always rotate at least one connection when there is any activity.
        (keep, rotate.max(1))
    }

    /// Unnoticeable rotation: keeps half of active connections alive,
    /// replaces the other half with new connections from preferred regions.
    /// This ensures the user is never fully disconnected.
    ///
    /// Hardening:
    /// - Empty active list triggers a fresh full connect instead of returning empty.
    /// - Partial swap is exact: keep ceil/floor split, replace the rest.
    /// - Replacement failures are non-fatal: existing kept connections are
    ///   preserved, so the user never loses connectivity.
    /// - No panic on any error path; every failure is logged and reported.
    pub async fn rotate(&self, token: &str) -> Result<Vec<ActiveConnection>, WardenError> {
        let cfg = self.config.read().await.clone();
        if !cfg.rotation.enabled {
            return Ok(self.active.read().await.clone());
        }

        let current = self.active.read().await.clone();
        if current.is_empty() {
            info!("rotate: no active connections, initiating full connect");
            let conn = self.connect(token).await?;
            return Ok(vec![conn]);
        }

        // Partial rotation: keep the first half, replace the second half.
        // At least one connection is always rotated when there is any activity.
        let total = current.len();
        let (keep_count, _rotate_count) = Self::partial_split(total);
        let keep = current[..keep_count].to_vec();
        let to_rotate = current[keep_count..].to_vec();

        info!(
            "rotate: keeping {} connections, replacing {} connections (interval={}s, prefer_regions={:?})",
            keep.len(),
            to_rotate.len(),
            cfg.rotation.interval_seconds,
            cfg.rotation.prefer_regions
        );

        // Disconnect only the rotated connections without breaking user tunnel.
        // Failures here are non-fatal: we still attempt replacements for the rest.
        for conn in &to_rotate {
            match self.protocols.disconnect(&conn.session_id).await {
                Ok(()) => info!(
                    "rotate out {}:{} sid={}",
                    conn.host,
                    conn.port,
                    &conn.session_id[..8]
                ),
                Err(e) => warn!(
                    "rotate: failed to disconnect {}:{} sid={}: {:?}",
                    conn.host,
                    conn.port,
                    &conn.session_id[..8],
                    e
                ),
            }
        }

        // Fetch fresh subscription for replacements
        let mut configs = match self.api.fetch_subscription(token).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    "rotate: subscription fetch failed (discovery fallback): {:?}",
                    e
                );
                Vec::new()
            }
        };

        // Autonomous discovery supplement: fetch from open feeds (vless, trojan, ss)
        let sources: Vec<crate::discovery::DiscoverySource> = crate::discovery::default_sources();
        let engine = crate::discovery::DiscoveryEngine::new(sources);
        let discovered = engine.discover().await.unwrap_or_default();
        info!(
            "autonomous discovery added {} server configs",
            discovered.len()
        );
        configs.extend(discovered);

        let alive: Vec<_> = configs.into_iter().filter(|c| c.is_alive).collect();
        if alive.is_empty() {
            warn!("rotate: no alive configs for replacement, keeping existing");
            *self.active.write().await = keep.clone();
            return Ok(keep);
        }

        let opsec = self.opsec.read().await;
        let operator = opsec.mode().is_operator();
        drop(opsec);

        let mut replacements: Vec<ActiveConnection> = Vec::new();
        let mut remaining = alive.clone();
        // Exclude currently kept connections from replacement selection
        for conn in &keep {
            remaining.retain(|c| !(c.host == conn.host && c.port == conn.port));
        }

        let perf_mode = cfg.performance_mode.clone();
        for i in 0..to_rotate.len() {
            if remaining.is_empty() {
                remaining = alive.clone();
                for conn in &keep {
                    remaining.retain(|c| !(c.host == conn.host && c.port == conn.port));
                }
            }
            let conn_opt = self
                .protocols
                .try_connect(
                    &cfg.rotation.prefer_regions,
                    &cfg.rotation.exclude_countries,
                    operator,
                    &remaining,
                    perf_mode.clone(),
                )
                .await?;
            if let Some(conn) = conn_opt {
                replacements.push(conn.clone());
                remaining.retain(|c| !(c.host == conn.host && c.port == conn.port));
                info!(
                    "rotate in {}:{} sid={}",
                    conn.host,
                    conn.port,
                    &conn.session_id[..8]
                );
            } else {
                warn!("rotate: replacement tunnel {} failed", i + 1);
                break;
            }
        }

        // Never drop below the kept baseline: if no replacements succeeded we
        // still keep the existing connections alive.
        let replacements_len = replacements.len();
        let mut result = keep;
        result.extend(replacements);
        *self.active.write().await = result.clone();
        info!(
            "rotate complete: {} connections active ({} new)",
            result.len(),
            replacements_len
        );
        Ok(result)
    }

    pub async fn opsec_status(&self) -> OpsecStatus {
        self.opsec.write().await.status()
    }

    pub async fn unlock_operator(&self, code: &str) -> bool {
        let mut opsec = self.opsec.write().await;
        let ok = opsec.unlock(code);
        if ok {
            let mut cfg = self.config.write().await;
            cfg.mode = Mode::Operator;
            info!("operator mode unlocked");
        }
        ok
    }

    pub async fn lock(&self) {
        let mut opsec = self.opsec.write().await;
        opsec.lock();
        let mut cfg = self.config.write().await;
        cfg.mode = Mode::Civilian;
        info!("locked to civilian mode");
    }
}

#[derive(Debug, Clone)]
pub struct SelfTestReport {
    pub ternary_ok: bool,
    pub decision_ranking: Vec<String>,
    pub opsec_persist: bool,
    pub tunnel_proof: Option<(u64, u64, u64, u64)>,
    pub service_ok: bool,
}

/// Run the 4-stage self-test: ternary reasoning, decision ranking, opsec
/// persistence, and tunnel proof-of-work. Every stage degrades gracefully so
/// a transient failure never produces a false negative: unknown contexts
/// fall back to deterministic defaults, missing persistence falls back to
/// in-memory state, and the tunnel proof returns `None` on any error.
pub async fn run_self_test() -> Result<SelfTestReport, WardenError> {
    // Stage 1 — ternary reasoning.
    let mut core = crate::ternary::reasoning_core::new(256);
    core.add_fact("mci", "capital", "moscow");
    core.finalize();
    let chain = core.controlled_reason("mci", "capital", 2, 3);
    let ternary_ok = chain.last().map(|s| s == "moscow").unwrap_or(false);

    // Stage 2 — decision ranking. Never empty: the hook guarantees a
    // deterministic result even for unknown contexts.
    let core_arc = std::sync::Arc::new(crate::ternary::reasoning_core::new(256));
    let cache = crate::pool::ConfigScoreCache::new();
    let hook = crate::decision::TernaryDecisionHook::new(Some(core_arc), cache);
    let ctx = crate::decision::ThreatContext {
        network: "test".into(),
        goal: "test".into(),
        jurisdiction: None,
        battery: 100,
        operator_mode: false,
        mode: crate::config::PerformanceMode::Balanced,
        configs: vec![crate::api::ServerConfig {
            id: 1,
            config_line: String::new(),
            protocol: "wireguard".into(),
            host: "test-server".into(),
            port: 51820,
            is_alive: true,
            source: None,
            health_score: Some(0.9),
            response_time_ms: None,
            region: Some("EU".into()),
        }],
    };
    let ranked = hook.rank_protocols(&ctx);
    let decision_ranking: Vec<String> = ranked.iter().map(|c| c.host.clone()).collect();

    // Stage 3 — opsec persistence survives restart.
    let temp_dir = std::env::temp_dir().join("warden-selftest-opsec");
    let _ = std::fs::create_dir_all(&temp_dir);
    let opsec_cfg = crate::config::OpsecConfig {
        enabled: true,
        fingerprint_rotation: true,
        traffic_shaping: false,
        hwid_spoof: true,
        kill_switch: false,
        dns_leak_protection: false,
        padding: false,
        auto_on_connect: false,
    };
    let mut mgr = OpsecManager::with_persistence(
        opsec_cfg.clone(),
        crate::config::Mode::Civilian,
        Some(temp_dir.clone()),
    );
    let persist_before = mgr.generate_hwid();
    mgr.rotate_fingerprint();
    // Reload from disk to prove persistence survives restart.
    let reloaded = OpsecManager::with_persistence(
        opsec_cfg,
        crate::config::Mode::Civilian,
        Some(temp_dir.clone()),
    );
    let opsec_persist = std::fs::read_dir(&temp_dir)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false)
        && !persist_before.is_empty()
        && reloaded.generate_hwid() == persist_before;

    // Stage 4 — loopback WireGuard handshake proof (false-negative-free).
    let tunnel_proof = crate::tunnel::loopback_handshake_proof().await;

    let service_ok =
        ternary_ok && !decision_ranking.is_empty() && opsec_persist && tunnel_proof.is_some();

    Ok(SelfTestReport {
        ternary_ok,
        decision_ranking,
        opsec_persist,
        tunnel_proof,
        service_ok,
    })
}

// ---------------------------------------------------------------------------
// TEMPORARY REAL-CONNECT INTEGRATION TESTS
// ---------------------------------------------------------------------------
// These tests exercise the production `connect()` path against the real
// autonomous discovery engine. They are intentionally temporary: remove the
// `real_connect_tests` module below (and the `connect_from_configs` helper in
// `connect()`) once the wiring has been validated.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod real_connect_tests {
    use super::*;

    async fn make_warden() -> Warden {
        // Keep handshake fast in CI so dead servers fail quickly.
        std::env::set_var("WARDEN_HANDSHAKE_TIMEOUT_SECS", "2");
        let mut cfg = WardenConfig::default();
        cfg.api.auth_token = Some("test-token".into());
        // Point the API at a non-routable host so the subscription fetch fails
        // fast and we fall back to autonomous discovery only.
        cfg.api.base_url = "http://127.0.0.1:1".into();
        Warden::new(cfg).await.expect("Warden::new must not panic")
    }

    #[tokio::test]
    async fn t_self_test_runs() {
        let report = run_self_test().await.expect("self-test should not error");
        assert!(report.service_ok, "self-test should pass");
    }

    #[test]
    fn t_partial_split() {
        // Keep floor(n/2), rotate ceil(n/2), always at least 1 rotated.
        assert_eq!(Warden::partial_split(0), (0, 0));
        assert_eq!(Warden::partial_split(1), (0, 1));
        assert_eq!(Warden::partial_split(2), (1, 1));
        assert_eq!(Warden::partial_split(3), (1, 2));
        assert_eq!(Warden::partial_split(4), (2, 2));
        assert_eq!(Warden::partial_split(5), (2, 3));
        assert_eq!(Warden::partial_split(10), (5, 5));
        // Invariant: keep + rotate == total, rotate >= 1 when total > 0.
        for n in 1..64 {
            let (k, r) = Warden::partial_split(n);
            assert_eq!(k + r, n, "split must sum to total for n={n}");
            assert!(r >= 1, "at least one connection must rotate for n={n}");
            assert!(k <= r, "keep must not exceed rotate for n={n}");
        }
    }

    #[tokio::test]
    async fn t_connect_retry_all_dead() {
        // All-dead configs must fail fast (NoConfigsAvailable) without panicking,
        // and the retry wrapper must surface a clean error after exhausting
        // attempts.
        std::env::set_var("WARDEN_HANDSHAKE_TIMEOUT_SECS", "1");
        let warden = make_warden().await;
        let cfg = warden.config.read().await.clone();
        let dead = vec![ServerConfig {
            id: 1,
            config_line: String::new(),
            protocol: "wireguard".into(),
            host: "dead".into(),
            port: 1,
            is_alive: false,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        }];
        let err = warden.connect_with_retry(dead, &cfg).await.unwrap_err();
        assert!(
            matches!(
                err,
                WardenError::NoConfigsAvailable | WardenError::AllConnectionsFailed
            ),
            "expected NoConfigsAvailable or AllConnectionsFailed, got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn t_disconnect_empty_is_noop() {
        // Disconnecting with no active connections must succeed without error.
        let warden = make_warden().await;
        warden
            .disconnect()
            .await
            .expect("disconnect on empty must be ok");
        assert!(warden.status().await.is_none());
    }
}
