//! Hardware-aware auto-tuning unit tests.
//!
//! These tests are kept in a dedicated module so they can run in CI without
//! the heavy async machinery of `Warden::new`. They cover the four required
//! scenarios: CPU detection, adaptive tuning, safe defaults, and apply.

use crate::calib::{AutoTuner, HardwareProfile, LiveMetrics, TunedConfig};

#[test]
fn t_detect_cpus() {
    let profile = HardwareProfile::detect();
    // available_parallelism always returns Ok(>=1) on a healthy platform.
    assert!(profile.cpus >= 1, "cpus must be >= 1, got {}", profile.cpus);
    assert!(!profile.os.is_empty(), "os must be populated");
    assert!(
        profile.memory_mb == 0 || profile.memory_mb >= 64,
        "memory_mb should be 0 (unknown) or a sane floor, got {}",
        profile.memory_mb
    );
}

#[test]
fn t_tune_defaults_safe() {
    let profile = HardwareProfile::detect();
    let tuner = AutoTuner::default();
    let tuned = tuner.tune(&profile, &LiveMetrics::default());

    // Invariants that must hold for every platform, even unknown hardware.
    assert!(
        tuned.parallel_connections >= 1,
        "parallel_connections must be >= 1, got {}",
        tuned.parallel_connections
    );
    assert!(
        tuned.parallel_connections <= 64,
        "parallel_connections must be sane, got {}",
        tuned.parallel_connections
    );
    assert!(
        tuned.rotation_interval_seconds >= 5,
        "rotation_interval_seconds must be >= 5, got {}",
        tuned.rotation_interval_seconds
    );
    assert!(
        tuned.rotation_interval_seconds <= 3600,
        "rotation_interval_seconds must be <= 3600, got {}",
        tuned.rotation_interval_seconds
    );
    assert!(
        tuned.handshake_timeout_secs >= 1,
        "handshake_timeout_secs must be >= 1, got {}",
        tuned.handshake_timeout_secs
    );
    assert!(
        tuned.handshake_timeout_secs <= 60,
        "handshake_timeout_secs must be <= 60, got {}",
        tuned.handshake_timeout_secs
    );
    assert!(
        tuned.worker_threads >= 1,
        "worker_threads must be >= 1, got {}",
        tuned.worker_threads
    );
    assert!(
        tuned.worker_threads <= 128,
        "worker_threads must be <= 128, got {}",
        tuned.worker_threads
    );
}

#[test]
fn t_tune_adapts() {
    // A 16-core box with fast, lossless links should drive parallelism up.
    let powerful = HardwareProfile {
        cpus: 16,
        memory_mb: 8192,
        os: "linux".into(),
    };
    let fast = LiveMetrics {
        latency_ms: 15.0,
        loss_pct: 0.0,
        throughput_mbps: 900.0,
    };
    let tuned_fast = AutoTuner::default().tune(&powerful, &fast);
    assert!(
        tuned_fast.parallel_connections >= 8,
        "fast 16-core link should raise parallelism, got {}",
        tuned_fast.parallel_connections
    );
    assert!(
        tuned_fast.handshake_timeout_secs <= 10,
        "high bandwidth should tighten handshake, got {}",
        tuned_fast.handshake_timeout_secs
    );

    // A 2-core box with a lossy, high-latency link must stay safe.
    let weak = HardwareProfile {
        cpus: 2,
        memory_mb: 512,
        os: "linux".into(),
    };
    let slow = LiveMetrics {
        latency_ms: 450.0,
        loss_pct: 8.0,
        throughput_mbps: 5.0,
    };
    let tuned_slow = AutoTuner::default().tune(&weak, &slow);
    assert!(
        tuned_slow.parallel_connections <= 4,
        "lossy 2-core link should keep parallelism low, got {}",
        tuned_slow.parallel_connections
    );
    assert!(
        tuned_slow.rotation_interval_seconds >= 30,
        "high latency should lengthen rotation interval, got {}",
        tuned_slow.rotation_interval_seconds
    );
    assert!(
        tuned_slow.handshake_timeout_secs >= 10,
        "low bandwidth should relax handshake, got {}",
        tuned_slow.handshake_timeout_secs
    );
}

#[test]
fn t_apply_does_not_break() {
    let profile = HardwareProfile::detect();
    let tuned = AutoTuner::default().tune(&profile, &LiveMetrics::default());
    let mut cfg = crate::config::WardenConfig::default();
    tuned.apply(&mut cfg);

    // apply() must never leave the config in an unusable state.
    assert!(cfg.rotation.interval_seconds >= 5);
    assert!(cfg.rotation.interval_seconds <= 3600);
    assert!(cfg.rotation.parallel_connections.unwrap() >= 1);
    assert!(cfg.rotation.handshake_timeout_secs.unwrap() >= 1);
    assert!(cfg.rotation.worker_threads.unwrap() >= 1);
    // Rotation defaults to enabled; the tuner must not flip it.
    assert!(cfg.rotation.enabled);
}
