//! Hardware-aware auto-tuning for Warden.
//!
//! Warden must adapt to every user's hardware. This module detects the host
//! CPU, memory and OS at startup, then derives safe, responsive tuning values
//! from live network metrics (latency, loss, throughput). It exposes:
//!
//! - [`HardwareProfile::detect`] — one-shot host introspection.
//! - [`AutoTuner`] — a stateful tuner that adapts on the fly.
//! - [`TunedConfig`] — the derived knobs, applied to [`WardenConfig`].
//!
//! Detection is best-effort: if any probe fails the field falls back to a
//! conservative default and existing behaviour is preserved.

use crate::config::WardenConfig;

/// Conservative bounds for every derived knob. These keep the system safe
/// even when detection partially fails.
pub const MIN_PARALLEL: usize = 1;
pub const MAX_PARALLEL: usize = 64;
pub const MIN_INTERVAL_SECS: u64 = 5;
pub const MAX_INTERVAL_SECS: u64 = 3600;
pub const MIN_HANDSHAKE_SECS: u64 = 1;
pub const MAX_HANDSHAKE_SECS: u64 = 60;
pub const MIN_WORKER_THREADS: usize = 1;
pub const MAX_WORKER_THREADS: usize = 128;

/// Live network metrics gathered during probing, fed to the tuner.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveMetrics {
    pub latency_ms: f64,
    pub loss_pct: f64,
    pub throughput_mbps: f64,
}

/// Snapshot of the host's compute resources, captured once at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareProfile {
    pub cpus: usize,
    pub memory_mb: u64,
    pub os: &'static str,
}

impl HardwareProfile {
    /// Detect the host profile. Never panics: every probe falls back to a
    /// conservative default so callers can always rely on a usable profile.
    pub fn detect() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);

        let memory_mb = read_meminfo_mb().unwrap_or(0);

        let os = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "freebsd") {
            "freebsd"
        } else {
            "unknown"
        };

        Self {
            cpus,
            memory_mb,
            os,
        }
    }
}

fn read_meminfo_mb() -> Option<u64> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let txt = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in txt.lines() {
        if line.starts_with("MemTotal:") {
            let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Derived tuning knobs, ready to apply to a [`WardenConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunedConfig {
    pub parallel_connections: usize,
    pub rotation_interval_seconds: u64,
    pub handshake_timeout_secs: u64,
    pub worker_threads: usize,
}

impl TunedConfig {
    /// Apply these values to a config, respecting any explicit overrides the
    /// user already set. Explicit overrides win so manual config always
    /// beats auto-tuning.
    pub fn apply(&self, cfg: &mut WardenConfig) {
        cfg.rotation.interval_seconds = cfg
            .rotation
            .interval_seconds
            .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS);
        if cfg.rotation.parallel_connections.is_none() {
            cfg.rotation.parallel_connections = Some(self.parallel_connections);
        }
        if cfg.rotation.handshake_timeout_secs.is_none() {
            cfg.rotation.handshake_timeout_secs = Some(self.handshake_timeout_secs);
        }
        if cfg.rotation.worker_threads.is_none() {
            cfg.rotation.worker_threads = Some(self.worker_threads);
        }
    }
}

/// Stateful auto-tuner. Holds no mutable state itself; `tune` is pure given a
/// profile and live metrics, which keeps it trivially testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct AutoTuner;

impl AutoTuner {
    /// Derive a [`TunedConfig`] from a hardware profile and live metrics.
    ///
    /// Rules (all clamped to safe bounds):
    /// - parallel_connections = cpus/2, capped, raised on low latency.
    /// - rotation_interval_seconds = latency-scaled, lengthened by loss.
    /// - handshake_timeout_secs = inverse-bandwidth, relaxed by loss/latency.
    /// - worker_threads = cpus, capped.
    pub fn tune(&self, profile: &HardwareProfile, m: &LiveMetrics) -> TunedConfig {
        let cpus = profile.cpus.max(1) as u64;

        // Parallel connections: base on cores, then scale by latency.
        let mut parallel = (cpus / 2).max(1).min(MAX_PARALLEL as u64) as usize;
        if m.latency_ms < 50.0 && m.loss_pct < 1.0 {
            parallel = (parallel * 2).min(MAX_PARALLEL);
        } else if m.latency_ms > 250.0 || m.loss_pct > 5.0 {
            parallel = (parallel / 2).max(MIN_PARALLEL);
        }

        // Rotation interval: 30s base, stretched by latency and loss.
        let mut interval: u64 = 30;
        if m.latency_ms > 200.0 {
            interval = 120;
        } else if m.latency_ms > 100.0 {
            interval = 60;
        }
        if m.loss_pct > 5.0 {
            interval = interval.saturating_mul(2).min(MAX_INTERVAL_SECS);
        }
        interval = interval.clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS);

        // Handshake timeout: 5s base, tightened by bandwidth, relaxed by loss.
        let mut handshake: u64 = 5;
        if m.throughput_mbps > 100.0 {
            handshake = 3;
        } else if m.throughput_mbps < 20.0 {
            handshake = 15;
        }
        if m.loss_pct > 5.0 || m.latency_ms > 200.0 {
            handshake = handshake.saturating_mul(2).min(MAX_HANDSHAKE_SECS);
        }
        handshake = handshake.clamp(MIN_HANDSHAKE_SECS, MAX_HANDSHAKE_SECS);

        let worker_threads = (cpus as usize).clamp(MIN_WORKER_THREADS, MAX_WORKER_THREADS);

        TunedConfig {
            parallel_connections: parallel.clamp(MIN_PARALLEL, MAX_PARALLEL),
            rotation_interval_seconds: interval,
            handshake_timeout_secs: handshake,
            worker_threads,
        }
    }
}
