use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ternary::reasoning_core::{new as new_core, ReasoningCore};
use crate::ternary::sharded_store::new as new_store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Discovery,
    Ranking,
    TrafficWatch,
    GeoEvasion,
    Rotation,
    Healing,
    Opsec,
}

impl Role {
    pub fn name(&self) -> &'static str {
        match self {
            Role::Discovery => "discovery",
            Role::Ranking => "ranking",
            Role::TrafficWatch => "traffic_watch",
            Role::GeoEvasion => "geo_evasion",
            Role::Rotation => "rotation",
            Role::Healing => "healing",
            Role::Opsec => "opsec",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubTask {
    ResolveFeed,
    ParseConfig,
    Probe,
    Score,
    InspectResponse,
    ClassifyBlock,
    SelectEvasion,
    PlanRotation,
    DetectDead,
    Reroute,
    FingerprintRotate,
    Persist,
}

impl SubTask {
    pub fn name(&self) -> &'static str {
        match self {
            SubTask::ResolveFeed => "resolve_feed",
            SubTask::ParseConfig => "parse_config",
            SubTask::Probe => "probe",
            SubTask::Score => "score",
            SubTask::InspectResponse => "inspect_response",
            SubTask::ClassifyBlock => "classify_block",
            SubTask::SelectEvasion => "select_evasion",
            SubTask::PlanRotation => "plan_rotation",
            SubTask::DetectDead => "detect_dead",
            SubTask::Reroute => "reroute",
            SubTask::FingerprintRotate => "fingerprint_rotate",
            SubTask::Persist => "persist",
        }
    }
}

pub struct RoleAssignment {
    pub role: Role,
    pub subtasks: Vec<SubTask>,
}

pub struct Mind {
    pub dim: usize,
    pub cores: std::collections::HashMap<Role, Arc<ReasoningCore>>,
    pub assignments: std::collections::HashMap<Role, RoleAssignment>,
}

impl Mind {
    pub fn new(dim: usize) -> Self {
        let mut cores = std::collections::HashMap::new();
        for role in [
            Role::Discovery,
            Role::Ranking,
            Role::TrafficWatch,
            Role::GeoEvasion,
            Role::Rotation,
            Role::Healing,
            Role::Opsec,
        ] {
            cores.insert(role, Arc::new(new_core(dim)));
        }
        let mut assignments = std::collections::HashMap::new();
        assignments.insert(
            Role::Discovery,
            RoleAssignment {
                role: Role::Discovery,
                subtasks: vec![SubTask::ResolveFeed, SubTask::ParseConfig],
            },
        );
        assignments.insert(
            Role::Ranking,
            RoleAssignment {
                role: Role::Ranking,
                subtasks: vec![SubTask::Probe, SubTask::Score],
            },
        );
        assignments.insert(
            Role::TrafficWatch,
            RoleAssignment {
                role: Role::TrafficWatch,
                subtasks: vec![SubTask::InspectResponse],
            },
        );
        assignments.insert(
            Role::GeoEvasion,
            RoleAssignment {
                role: Role::GeoEvasion,
                subtasks: vec![SubTask::ClassifyBlock, SubTask::SelectEvasion],
            },
        );
        assignments.insert(
            Role::Rotation,
            RoleAssignment {
                role: Role::Rotation,
                subtasks: vec![SubTask::PlanRotation],
            },
        );
        assignments.insert(
            Role::Healing,
            RoleAssignment {
                role: Role::Healing,
                subtasks: vec![SubTask::DetectDead, SubTask::Reroute],
            },
        );
        assignments.insert(
            Role::Opsec,
            RoleAssignment {
                role: Role::Opsec,
                subtasks: vec![SubTask::FingerprintRotate, SubTask::Persist],
            },
        );
        Mind {
            dim,
            cores,
            assignments,
        }
    }

    pub fn core(&self, role: Role) -> Arc<ReasoningCore> {
        self.cores.get(&role).cloned().unwrap_or_else(|| {
            self.cores
                .get(&Role::Discovery)
                .cloned()
                .expect("discovery core always present")
        })
    }

    pub fn add_fact(&self, _role: Role, _s: &str, _p: &str, _o: &str) {
        // ReasoningCore is wrapped in Arc and the inner is not Clone (finalize
        // mutates shared state). Real writers go through protocols/discovery
        // which own the core; this stub keeps the public API stable.
    }
    pub fn stats(&self) -> Vec<(Role, usize, usize)> {
        self.cores
            .iter()
            .map(|(role, core)| {
                let s = core.get_stats();
                let entities: usize = s.get("entities").and_then(|v| v.parse().ok()).unwrap_or(0);
                let facts: usize = s.get("facts").and_then(|v| v.parse().ok()).unwrap_or(0);
                (*role, facts, entities)
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct GeoBlockSignal {
    pub host: String,
    pub status: u16,
    pub body_excerpt: String,
    pub detected_at: Instant,
    pub reason: BlockReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// "not available in your region", "unavailable in your country"
    RegionExplicit,
    /// 451 status
    LegalStatus,
    /// 403 with strong geo signal
    ForbiddenWithGeo,
    /// Redirect to a region-locked landing
    RedirectToLanding,
    /// No signal, but we retry-failed
    Unknown,
}

impl BlockReason {
    pub fn classify(status: u16, body: &str) -> Self {
        let lower = body.to_lowercase();
        if status == 451 {
            return BlockReason::LegalStatus;
        }
        let region_keys = [
            "not available in your country",
            "not available in your region",
            "unavailable in your region",
            "this content is not available",
            "is not available in your",
            "geo-restricted",
            "geoblocked",
            "vasha strana",
            "nedostupno v vashey strane",
            "nedostupen v vashey strane",
        ];
        for k in region_keys.iter() {
            if lower.contains(k) {
                return BlockReason::RegionExplicit;
            }
        }
        if status == 403 && (lower.contains("region") || lower.contains("country")) {
            return BlockReason::ForbiddenWithGeo;
        }
        if status == 302 || status == 301 {
            return BlockReason::RedirectToLanding;
        }
        BlockReason::Unknown
    }
}

pub struct TrafficWatchdog {
    pub enabled: bool,
    pub poll_interval: Duration,
    pub signals: Vec<GeoBlockSignal>,
    pub last_eval: Option<Instant>,
}

impl TrafficWatchdog {
    pub fn new() -> Self {
        TrafficWatchdog {
            enabled: false,
            poll_interval: Duration::from_secs(30),
            signals: Vec::new(),
            last_eval: None,
        }
    }

    pub fn enable(&mut self) {
        self.enabled = true;
        self.last_eval = Some(Instant::now());
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    pub fn record(&mut self, signal: GeoBlockSignal) {
        if !self.enabled {
            return;
        }
        self.signals.retain(|s| {
            signal.detected_at.duration_since(s.detected_at) < Duration::from_secs(600)
        });
        if signal.reason != BlockReason::Unknown {
            self.signals.push(signal);
        }
    }

    pub fn should_evade(&self) -> bool {
        if !self.enabled {
            return false;
        }
        self.signals
            .iter()
            .filter(|s| s.detected_at.elapsed() < Duration::from_secs(60))
            .count()
            >= 2
    }

    pub fn recent_reason(&self) -> Option<BlockReason> {
        self.signals
            .iter()
            .max_by_key(|s| s.detected_at)
            .map(|s| s.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mind_assigns_each_role() {
        let mind = Mind::new(64);
        for role in [
            Role::Discovery,
            Role::Ranking,
            Role::TrafficWatch,
            Role::GeoEvasion,
            Role::Rotation,
            Role::Healing,
            Role::Opsec,
        ] {
            let core = mind.core(role);
            assert!(Arc::strong_count(&core) >= 1, "core must be held");
            assert!(mind.assignments.contains_key(&role));
            assert!(!mind.assignments[&role].subtasks.is_empty());
        }
    }

    #[test]
    fn block_classifier_geo_text() {
        let r = BlockReason::classify(200, "This content is not available in your region");
        assert_eq!(r, BlockReason::RegionExplicit);
    }

    #[test]
    fn block_classifier_legal_status() {
        let r = BlockReason::classify(451, "");
        assert_eq!(r, BlockReason::LegalStatus);
    }

    #[test]
    fn watchdog_only_records_when_enabled() {
        let mut wd = TrafficWatchdog::new();
        let sig = GeoBlockSignal {
            host: "x".into(),
            status: 200,
            body_excerpt: "not available in your region".into(),
            detected_at: Instant::now(),
            reason: BlockReason::RegionExplicit,
        };
        wd.record(sig.clone());
        assert!(wd.signals.is_empty());
        wd.enable();
        wd.record(sig.clone());
        wd.record(sig);
        assert_eq!(wd.signals.len(), 2);
        assert!(wd.should_evade());
    }
}
