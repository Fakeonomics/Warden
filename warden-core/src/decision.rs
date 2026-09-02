use std::sync::Arc;

use crate::config::PerformanceMode;
use crate::pool::{ConfigScoreCache, QualityMetrics};
use crate::ternary::reasoning_core::{new, ReasoningCore};
use crate::ServerConfig;

pub struct ThreatContext {
    pub network: String,
    pub goal: String,
    pub jurisdiction: Option<String>,
    pub battery: u8,
    pub operator_mode: bool,
    pub mode: PerformanceMode,
    pub configs: Vec<ServerConfig>,
}

pub trait DecisionHook {
    fn rank_protocols(&self, ctx: &ThreatContext) -> Vec<ServerConfig>;
    fn name(&self) -> &'static str;
}

pub struct NoopDecisionHook;

impl DecisionHook for NoopDecisionHook {
    fn rank_protocols(&self, ctx: &ThreatContext) -> Vec<ServerConfig> {
        let mut v = ctx.configs.clone();
        v.sort_by(|a, b| {
            let sa = a.health_score.unwrap_or(0.0);
            let sb = b.health_score.unwrap_or(0.0);
            sb.partial_cmp(&sa).unwrap()
        });
        v
    }
    fn name(&self) -> &'static str {
        "noop"
    }
}

pub struct TernaryDecisionHook {
    pub core: Option<Arc<ReasoningCore>>,
    pub cache: ConfigScoreCache,
}

impl TernaryDecisionHook {
    pub fn new(core: Option<Arc<ReasoningCore>>, cache: ConfigScoreCache) -> Self {
        TernaryDecisionHook { core, cache }
    }

    fn score_metrics(&self, cfg: &ServerConfig, mode: &PerformanceMode) -> f64 {
        let m = self
            .cache
            .get(&cfg.id.to_string())
            .map(|e| &e.metrics)
            .unwrap_or(&QualityMetrics {
                latency_ms: 999.0,
                throughput_mbps: 0.0,
                handshake_ok: false,
                dpi_resistance: false,
                last_tested: 0,
            });
        match mode {
            PerformanceMode::Speed => crate::quality::score_speed(m),
            PerformanceMode::Stealth => crate::quality::score_stealth(m),
            PerformanceMode::Balanced => crate::quality::score_balanced(m),
        }
    }
}

impl DecisionHook for TernaryDecisionHook {
    fn rank_protocols(&self, ctx: &ThreatContext) -> Vec<ServerConfig> {
        // Unknown context: never return an empty ranking. Fall back to a
        // deterministic health-score sort so downstream connect loops always
        // have at least one candidate to try.
        if ctx.configs.is_empty() {
            return Vec::new();
        }

        if self.core.is_none() {
            let mut ranked: Vec<ServerConfig> = ctx.configs.clone();
            ranked.sort_by(|a, b| {
                let mut sa = a.health_score.unwrap_or(0.0);
                let mut sb = b.health_score.unwrap_or(0.0);
                if self.cache.get(&a.id.to_string()).is_some() {
                    sa += 0.1;
                }
                if self.cache.get(&b.id.to_string()).is_some() {
                    sb += 0.1;
                }
                sb.partial_cmp(&sa).unwrap()
            });
            return ranked;
        }

        let core = self.core.as_ref().unwrap();
        let mut kb = new(core.dim);

        let mut owned: Vec<(String, String, String)> = Vec::new();
        for cfg in &ctx.configs {
            let id = cfg.id.to_string();
            owned.push((id.clone(), "uses".into(), cfg.protocol.clone()));
            owned.push((
                id.clone(),
                "region".into(),
                cfg.region.clone().unwrap_or_else(|| "unknown".into()),
            ));
            if let Some(entry) = self.cache.get(&id) {
                owned.push((
                    id.clone(),
                    "latency_ms".into(),
                    entry.metrics.latency_ms.to_string(),
                ));
                owned.push((
                    id.clone(),
                    "throughput".into(),
                    entry.metrics.throughput_mbps.to_string(),
                ));
                owned.push((
                    id.clone(),
                    "resists_dpi".into(),
                    if entry.metrics.dpi_resistance {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                ));
            } else {
                owned.push((id.clone(), "latency_ms".into(), "999".into()));
                owned.push((id.clone(), "throughput".into(), "0".into()));
                owned.push((id, "resists_dpi".into(), "no".into()));
            }
        }

        let fact_refs: Vec<(&str, &str, &str)> = owned
            .iter()
            .map(|(s, p, o)| (s.as_str(), p.as_str(), o.as_str()))
            .collect();
        kb.add_facts(&fact_refs);
        kb.finalize();

        let goal_pred = match ctx.mode {
            PerformanceMode::Speed => "fastest",
            PerformanceMode::Stealth => "stealthiest",
            PerformanceMode::Balanced => "reliable",
        };

        let _chain = kb.controlled_reason("global", goal_pred, 2, 4);

        let mode = &ctx.mode;
        let mut scored: Vec<(ServerConfig, f64)> = ctx
            .configs
            .iter()
            .map(|cfg| (cfg.clone(), self.score_metrics(cfg, mode)))
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scored.into_iter().map(|(cfg, _)| cfg).collect()
    }

    fn name(&self) -> &'static str {
        "ternary"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerConfig;
    use crate::pool::QualityMetrics;

    #[test]
    fn mode_ranking_differs() {
        let fast_leaky = ServerConfig {
            id: 1,
            config_line: String::new(),
            protocol: "wireguard".into(),
            host: "fast-leaky".into(),
            port: 51820,
            is_alive: true,
            source: None,
            health_score: Some(0.5),
            response_time_ms: None,
            region: Some("US".into()),
        };
        let slow_stealth = ServerConfig {
            id: 2,
            config_line: String::new(),
            protocol: "vless".into(),
            host: "slow-stealth".into(),
            port: 443,
            is_alive: true,
            source: None,
            health_score: Some(0.9),
            response_time_ms: None,
            region: Some("DE".into()),
        };

        let core = Arc::new(new(256));
        let mut cache = ConfigScoreCache::new();
        cache.put(
            "1",
            QualityMetrics {
                latency_ms: 20.0,
                throughput_mbps: 900.0,
                handshake_ok: true,
                dpi_resistance: false,
                last_tested: 0,
            },
        );
        cache.put(
            "2",
            QualityMetrics {
                latency_ms: 150.0,
                throughput_mbps: 400.0,
                handshake_ok: true,
                dpi_resistance: true,
                last_tested: 0,
            },
        );

        let hook = TernaryDecisionHook::new(Some(core), cache);

        let speed_ctx = ThreatContext {
            network: "global".into(),
            goal: "connect".into(),
            jurisdiction: None,
            battery: 100,
            operator_mode: false,
            mode: PerformanceMode::Speed,
            configs: vec![fast_leaky.clone(), slow_stealth.clone()],
        };
        let speed_ranked = hook.rank_protocols(&speed_ctx);
        println!(
            "[decision] Speed rank  -> {:?}",
            speed_ranked
                .iter()
                .map(|c| c.host.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(speed_ranked[0].host, "fast-leaky");

        let stealth_ctx = ThreatContext {
            network: "global".into(),
            goal: "connect".into(),
            jurisdiction: None,
            battery: 100,
            operator_mode: false,
            mode: PerformanceMode::Stealth,
            configs: vec![fast_leaky, slow_stealth],
        };
        let stealth_ranked = hook.rank_protocols(&stealth_ctx);
        println!(
            "[decision] Stealth rank -> {:?}",
            stealth_ranked
                .iter()
                .map(|c| c.host.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(stealth_ranked[0].host, "slow-stealth");
    }

    #[test]
    fn unknown_context_never_empty() {
        let hook = TernaryDecisionHook::new(None, ConfigScoreCache::new());
        let ctx = ThreatContext {
            network: "unknown".into(),
            goal: "unknown".into(),
            jurisdiction: None,
            battery: 0,
            operator_mode: false,
            mode: PerformanceMode::Balanced,
            configs: vec![ServerConfig {
                id: 9,
                config_line: String::new(),
                protocol: "wireguard".into(),
                host: "x".into(),
                port: 51820,
                is_alive: true,
                source: None,
                health_score: Some(0.1),
                response_time_ms: None,
                region: None,
            }],
        };
        let ranked = hook.rank_protocols(&ctx);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].host, "x");
    }

    #[test]
    fn empty_configs_returns_empty_not_panic() {
        let hook = TernaryDecisionHook::new(None, ConfigScoreCache::new());
        let ctx = ThreatContext {
            network: "n".into(),
            goal: "g".into(),
            jurisdiction: None,
            battery: 0,
            operator_mode: false,
            mode: PerformanceMode::Balanced,
            configs: vec![],
        };
        assert!(hook.rank_protocols(&ctx).is_empty());
    }

    #[test]
    fn unknown_jurisdiction_handled() {
        // An exotic jurisdiction string must not break ranking; it is just a
        // context field, not a control-flow signal.
        let hook = TernaryDecisionHook::new(None, ConfigScoreCache::new());
        let ctx = ThreatContext {
            network: "tor".into(),
            goal: "evade".into(),
            jurisdiction: Some("XK".into()),
            battery: 12,
            operator_mode: true,
            mode: PerformanceMode::Stealth,
            configs: vec![ServerConfig {
                id: 1,
                config_line: String::new(),
                protocol: "vless".into(),
                host: "h1".into(),
                port: 443,
                is_alive: true,
                source: None,
                health_score: Some(0.7),
                response_time_ms: None,
                region: Some("EU".into()),
            }],
        };
        let ranked = hook.rank_protocols(&ctx);
        assert_eq!(ranked.len(), 1);
    }

    #[test]
    fn battery_and_operator_mode_are_context_only() {
        // Extreme context values must not change ranking order beyond the
        // deterministic health-score sort.
        let hook = TernaryDecisionHook::new(None, ConfigScoreCache::new());
        let mk = |host: String, hs| ServerConfig {
            id: 0,
            config_line: String::new(),
            protocol: "wireguard".into(),
            host,
            port: 51820,
            is_alive: true,
            source: None,
            health_score: hs,
            response_time_ms: None,
            region: Some("US".into()),
        };
        let ctx = ThreatContext {
            network: "n".into(),
            goal: "g".into(),
            jurisdiction: None,
            battery: 255,
            operator_mode: true,
            mode: PerformanceMode::Speed,
            configs: vec![
                mk("low".to_string(), Some(0.2)),
                mk("high".to_string(), Some(0.9)),
            ],
        };
        let ranked = hook.rank_protocols(&ctx);
        assert_eq!(ranked[0].host, "high");
    }
}
