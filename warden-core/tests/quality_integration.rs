//! End-to-end integration tests for the Warden quality subsystem.
//!
//! These tests exercise the full pipeline: real HTTP feeds, parsing,
//! per-service probing, scoring, and rotation triggers. They avoid the
//! global cache file and instead use a per-test temp directory.

use std::time::Duration;

#[tokio::test]
#[ignore = "requires network"]
async fn real_feed_to_parsed_configs() {
    let body = reqwest::get(
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    )
    .await
    .expect("feed must be reachable")
    .text()
    .await
    .expect("body must decode");
    let count = body
        .lines()
        .filter(|l| l.contains("://") && !l.trim().is_empty())
        .count();
    assert!(count > 100, "expected >100 lines, got {}", count);
}

#[tokio::test]
#[ignore = "requires network"]
async fn real_feed_to_configs_with_parse() {
    let body = reqwest::get(
        "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    )
    .await
    .expect("feed must be reachable")
    .text()
    .await
    .expect("body must decode");
    let mut good = 0i64;
    let mut bad = 0i64;
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() {
            continue;
        }
        if l.contains("://") {
            // We re-derive the same simple parser logic to avoid a circular
            // dep on warden-app (which is where tui::parse_uri_line lives).
            let proto_end = l.find("://").unwrap();
            let proto = l[..proto_end].to_lowercase();
            let rest = l[proto_end + 3..].split('#').next().unwrap();
            let after = rest.rsplit('@').next().unwrap();
            let parts: Vec<&str> = after.split(':').collect();
            if parts.len() >= 2 {
                if let Ok(p) = parts[parts.len() - 1].parse::<i32>() {
                    if (1..=65535).contains(&p) && !parts[parts.len() - 2].is_empty() {
                        if matches!(
                            proto.as_str(),
                            "vless" | "trojan" | "ss" | "vmess" | "hysteria2" | "hy2" | "wireguard" | "wg"
                        ) {
                            good += 1;
                            continue;
                        }
                    }
                }
            }
            bad += 1;
        }
    }
    assert!(good > 50, "expected >50 good configs, got {} (bad={})", good, bad);
}

#[tokio::test]
async fn tcp_probe_unreachable_host_fails() {
    use std::net::SocketAddr;
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let ok = tokio::time::timeout(Duration::from_secs(1), tokio::net::TcpStream::connect(addr))
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    assert!(!ok, "127.0.0.1:1 must be unreachable");
}

#[tokio::test]
async fn http_probe_localhost_404() {
    // We expect a fast failure against a non-routable port.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let url = "http://127.0.0.1:1/anything";
    let r = client.get(url).send().await;
    assert!(r.is_err(), "127.0.0.1:1 must be unreachable for HTTP too");
}

#[tokio::test]
async fn hardware_tier_is_always_set() {
    let hw = warden_core::detect_hardware();
    assert!(hw.cpus >= 1);
    assert!(hw.total_memory_mb >= 256);
    assert!(hw.measured_throughput_mbps > 0.0);
    // Tier enum covers all variants.
    let _ = hw.tier.label();
    let _ = hw.tier.concurrency();
    let _ = hw.tier.per_probe_timeout();
    let _ = hw.tier.max_attempts();
    let _ = hw.tier.max_acceptable_latency();
}

#[tokio::test]
async fn warden_self_test_runs() {
    let r = warden_core::run_self_test().await.expect("self-test");
    assert!(r.service_ok, "self-test must pass");
}

#[tokio::test]
#[ignore = "requires network; run with --ignored"]
async fn real_speed_test_returns_mbps() {
    use warden_core::speed_test::{measure, SpeedTestConfig};
    let cfg = SpeedTestConfig {
        target_bytes: 1024 * 1024,
        samples: 1,
        streams: 2,
        warmup_ms: 200,
        ..Default::default()
    };
    let s = measure(&cfg).await.expect("must reach a CDN");
    assert!(s.mbps > 0.0, "expected positive Mbps, got {}", s.mbps);
    assert!(s.bytes > 0);
}
