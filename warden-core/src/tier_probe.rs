use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HardwareTier {
    /// Embedded / old laptop / weak uplink
    Low,
    /// Mainstream desktop / 100 Mbps uplink
    Mid,
    /// Gaming / workstation / gigabit
    High,
    /// Datacenter-grade
    Ultra,
}

impl HardwareTier {
    pub fn label(&self) -> &'static str {
        match self {
            HardwareTier::Low => "low",
            HardwareTier::Mid => "mid",
            HardwareTier::High => "high",
            HardwareTier::Ultra => "ultra",
        }
    }

    /// Concurrent probe workers.
    pub fn concurrency(&self) -> usize {
        match self {
            HardwareTier::Low => 4,
            HardwareTier::Mid => 16,
            HardwareTier::High => 64,
            HardwareTier::Ultra => 256,
        }
    }

    /// Per-probe timeout.
    pub fn per_probe_timeout(&self) -> Duration {
        match self {
            HardwareTier::Low => Duration::from_secs(8),
            HardwareTier::Mid => Duration::from_secs(5),
            HardwareTier::High => Duration::from_secs(3),
            HardwareTier::Ultra => Duration::from_secs(2),
        }
    }

    /// How many candidates to exhaust before declaring "no good server found".
    /// Higher tier = willing to burn more probes to find the best one.
    pub fn max_attempts(&self) -> usize {
        match self {
            HardwareTier::Low => 30,
            HardwareTier::Mid => 100,
            HardwareTier::High => 400,
            HardwareTier::Ultra => 2000,
        }
    }

    /// Latency target: probes above this are considered bad even if alive.
    pub fn max_acceptable_latency(&self) -> Duration {
        match self {
            HardwareTier::Low => Duration::from_millis(800),
            HardwareTier::Mid => Duration::from_millis(400),
            HardwareTier::High => Duration::from_millis(200),
            HardwareTier::Ultra => Duration::from_millis(120),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HardwareReport {
    pub cpus: usize,
    pub total_memory_mb: u64,
    pub uplink_kind: UplinkKind,
    pub measured_throughput_mbps: f64,
    pub tier: HardwareTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UplinkKind {
    Dialup,
    Broadband,
    FastEthernet,
    Gigabit,
    TenGig,
}

impl UplinkKind {
    pub fn label(&self) -> &'static str {
        match self {
            UplinkKind::Dialup => "dialup",
            UplinkKind::Broadband => "broadband",
            UplinkKind::FastEthernet => "fast_eth",
            UplinkKind::Gigabit => "gigabit",
            UplinkKind::TenGig => "10g",
        }
    }
}

pub fn detect_tier(cpus: usize, mem_mb: u64) -> HardwareTier {
    match (cpus, mem_mb) {
        (c, m) if c >= 16 && m >= 16384 => HardwareTier::Ultra,
        (c, m) if c >= 8 && m >= 8192 => HardwareTier::High,
        (c, m) if c >= 4 && m >= 4096 => HardwareTier::Mid,
        _ => HardwareTier::Low,
    }
}

pub fn detect_uplink(throughput_mbps: f64) -> UplinkKind {
    if throughput_mbps >= 5000.0 {
        UplinkKind::TenGig
    } else if throughput_mbps >= 800.0 {
        UplinkKind::Gigabit
    } else if throughput_mbps >= 80.0 {
        UplinkKind::FastEthernet
    } else if throughput_mbps >= 5.0 {
        UplinkKind::Broadband
    } else {
        UplinkKind::Dialup
    }
}

pub fn measure_uplink_approx() -> f64 {
    // Best-effort: read /sys/class/net for nominal link speed, default 100 Mbps.
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut max_mbps = 0.0;
            for entry in entries.flatten() {
                let path = entry.path().join("speed");
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(mbps) = s.trim().parse::<f64>() {
                        if mbps > max_mbps {
                            max_mbps = mbps;
                        }
                    }
                }
            }
            if max_mbps > 0.0 {
                return max_mbps;
            }
        }
    }
    100.0
}

pub fn detect_hardware() -> HardwareReport {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    let total_memory_mb = detect_total_memory_mb();
    let measured = measure_uplink_approx();
    let mut tier = detect_tier(cpus, total_memory_mb);
    if measured >= 5000.0 {
        tier = tier.max(HardwareTier::Ultra);
    } else if measured >= 800.0 {
        tier = tier.max(HardwareTier::High);
    } else if measured >= 80.0 {
        tier = tier.max(HardwareTier::Mid);
    }
    HardwareReport {
        cpus,
        total_memory_mb,
        uplink_kind: detect_uplink(measured),
        measured_throughput_mbps: measured,
        tier,
    }
}

#[cfg(target_os = "linux")]
fn detect_total_memory_mb() -> u64 {
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        for line in s.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        return kb / 1024;
                    }
                }
            }
        }
    }
    4096
}

#[cfg(not(target_os = "linux"))]
fn detect_total_memory_mb() -> u64 {
    4096
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_thresholds() {
        assert_eq!(detect_tier(2, 2048), HardwareTier::Low);
        assert_eq!(detect_tier(4, 4096), HardwareTier::Mid);
        assert_eq!(detect_tier(8, 8192), HardwareTier::High);
        assert_eq!(detect_tier(16, 16384), HardwareTier::Ultra);
    }

    #[test]
    fn uplink_classes() {
        assert_eq!(detect_uplink(1.0), UplinkKind::Dialup);
        assert_eq!(detect_uplink(50.0), UplinkKind::Broadband);
        assert_eq!(detect_uplink(150.0), UplinkKind::FastEthernet);
        assert_eq!(detect_uplink(1000.0), UplinkKind::Gigabit);
        assert_eq!(detect_uplink(10000.0), UplinkKind::TenGig);
    }

    #[test]
    fn concurrency_scales() {
        assert!(HardwareTier::Ultra.concurrency() > HardwareTier::High.concurrency());
        assert!(HardwareTier::High.concurrency() > HardwareTier::Mid.concurrency());
        assert!(HardwareTier::Mid.concurrency() > HardwareTier::Low.concurrency());
    }

    #[test]
    fn detect_returns_sane_report() {
        let r = detect_hardware();
        assert!(r.cpus >= 1);
        assert!(r.total_memory_mb >= 256);
        assert!(r.measured_throughput_mbps > 0.0);
    }
}
