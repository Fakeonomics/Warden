use std::sync::Arc;
use warden_core::ternary::reasoning_core::{new, ReasoningCore};
use warden_core::config::PerformanceMode;
use warden_core::decision::{DecisionHook, TernaryDecisionHook, ThreatContext};
use warden_core::api::ServerConfig;
use warden_core::pool::{ConfigPool, ConfigScoreCache, QualityMetrics};

fn main() {
    // (1) ReasoningCore::new(256) + controlled_reason('mci','capital',2,3)
    let core = new(256);
    let mut kb = new(256);
    kb.add_fact("mci", "capital", "moscow");
    kb.finalize();
    let chain = kb.controlled_reason("mci", "capital", 2, 3);
    println!("Chain: {:?}", chain);

    // (2) TernaryDecisionHook with PerformanceMode::Speed ranking fast-leaky vs slow-stealth
    let core_arc = Arc::new(ReasoningCore::new(256));
    let mut cache = ConfigScoreCache::new();
    cache.put("1", QualityMetrics { latency_ms: 20.0, throughput_mbps: 900.0, handshake_ok: true, dpi_resistance: false, last_tested: 0 });
    cache.put("2", QualityMetrics { latency_ms: 150.0, throughput_mbps: 400.0, handshake_ok: true, dpi_resistance: true, last_tested: 0 });

    let hook = TernaryDecisionHook::new(Some(core_arc), cache);
    let fast_leaky = ServerConfig { id: 1, config_line: String::new(), protocol: "wireguard".into(), host: "fast-leaky".into(), port: 51820, is_alive: true, source: None, health_score: Some(0.5), response_time_ms: None, region: Some("US".into()) };
    let slow_stealth = ServerConfig { id: 2, config_line: String::new(), protocol: "vless".into(), host: "slow-stealth".into(), port: 443, is_alive: true, source: None, health_score: Some(0.9), response_time_ms: None, region: Some("DE".into()) };
    let ctx = ThreatContext { network: "global".into(), goal: "connect".into(), jurisdiction: None, battery: 100, operator_mode: false, mode: PerformanceMode::Speed, configs: vec![fast_leaky.clone(), slow_stealth.clone()] };
    let ranked = hook.rank_protocols(&ctx);
    println!("Speed ranking: {:?}", ranked.iter().map(|c| c.host.as_str()).collect::<Vec<_>>());

    // (3) ConfigPool + ConfigScoreCache
    let pool = ConfigPool::new(vec![fast_leaky, slow_stealth], ConfigScoreCache::new(), Arc::new(warden_core::pool::MockProbe));
    println!("Pool configs: {}", pool.configs.len());
}
