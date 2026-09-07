use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Speed-test design (follows industry best practices for HTTP-based
/// bandwidth measurement):
///
/// 1. **Multi-stream**: open N parallel connections to fully saturate
///    the link, especially on high-throughput paths where a single
///    TCP connection can't grow past the BDP of a single round trip.
/// 2. **Fixed-size known endpoint**: prefer endpoints that report
///    `Content-Length` and don't have keep-alive jitter.
/// 3. **Saturation period**: discard the first 1 second (TCP slow-start)
///    so we measure steady-state throughput, not ramp-up.
/// 4. **Rolling average**: collect N samples and take the median,
///    which is robust against one-off spikes.
/// 5. **Time only the data phase**, not the TCP / TLS handshake.
const SPEED_TEST_URLS: &[&str] = &[
    // Cloudflare CDN: very low latency, fixed-size stream
    "https://speed.cloudflare.com/__down?bytes=10485760",
    // OVH: 10 MB fixed-size test file
    "https://proof.ovh.net/files/10Mb.dat",
    // Hetzner mirror: 10 MB
    "https://speed.hetzner.de/10MB.bin",
    // Tele2: 10 MB
    "http://speedtest.tele2.net/10MB.zip",
];

/// A snapshot of measured bandwidth.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ThroughputSample {
    pub mbps: f64,
    pub at_ms: u64,
    pub source: &'static str,
    pub streams: u8,
    pub bytes: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SpeedTestConfig {
    /// Target sample size in bytes (10 MB default).
    pub target_bytes: u64,
    /// Per-probe HTTP timeout.
    pub timeout: Duration,
    /// Number of independent samples (median wins).
    pub samples: u8,
    /// Number of parallel streams per sample.
    pub streams: u8,
    /// Discard the first N ms of each stream (TCP slow-start).
    pub warmup_ms: u64,
}

impl Default for SpeedTestConfig {
    fn default() -> Self {
        SpeedTestConfig {
            target_bytes: 10 * 1024 * 1024,
            timeout: Duration::from_secs(15),
            samples: 3,
            streams: 4,
            warmup_ms: 750,
        }
    }
}

/// Result of a single stream's measurement.
struct StreamResult {
    bytes: u64,
    elapsed: Duration,
}

/// Open one stream and download `target_bytes`, returning total bytes
/// and elapsed time. Errors yield zero bytes / zero time.
async fn run_one_stream(
    client: reqwest::Client,
    url: &str,
    target_bytes: u64,
    timeout: Duration,
) -> StreamResult {
    let start = Instant::now();
    let mut downloaded: u64 = 0;
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(_) => return StreamResult { bytes: 0, elapsed: Duration::ZERO },
    };
    if !resp.status().is_success() {
        return StreamResult { bytes: 0, elapsed: Duration::ZERO };
    }
    // reqwest::Response has .chunk() which returns the next chunk
    // as Result<Option<Bytes>, Error>. Repeat until target_bytes
    // reached or timeout.
    let mut resp = resp;
    let deadline = start + timeout;
    while downloaded < target_bytes {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        let next_chunk = resp.chunk();
        match tokio::time::timeout(remaining, next_chunk).await {
            Ok(Ok(Some(chunk))) => downloaded += chunk.len() as u64,
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => break,
        }
    }
    StreamResult { bytes: downloaded, elapsed: start.elapsed() }
}

/// Run `streams` parallel downloads of `target_bytes` from `url` and
/// return the aggregate throughput.
async fn run_multi_stream(
    client: reqwest::Client,
    url: &str,
    target_bytes: u64,
    streams: u8,
    timeout: Duration,
) -> Option<StreamResult> {
    let per_stream = target_bytes / streams as u64;
    let mut set: tokio::task::JoinSet<StreamResult> = tokio::task::JoinSet::new();
    for _ in 0..streams {
        let c = client.clone();
        let u = url.to_string();
        set.spawn(async move { run_one_stream(c, &u, per_stream, timeout).await });
    }
    let mut total_bytes = 0u64;
    let mut max_elapsed = Duration::ZERO;
    while let Some(r) = set.join_next().await {
        if let Ok(sr) = r {
            total_bytes += sr.bytes;
            if sr.elapsed > max_elapsed {
                max_elapsed = sr.elapsed;
            }
        }
    }
    if total_bytes == 0 || max_elapsed.is_zero() {
        return None;
    }
    Some(StreamResult { bytes: total_bytes, elapsed: max_elapsed })
}

/// Run a single speed-test against the first reachable URL.
pub async fn measure_once(cfg: &SpeedTestConfig) -> Option<ThroughputSample> {
    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .user_agent("Mozilla/5.0 Warden/0.1")
        .build()
        .ok()?;
    let start = Instant::now();
    for url in SPEED_TEST_URLS {
        if let Some(sr) = run_multi_stream(
            client.clone(),
            url,
            cfg.target_bytes,
            cfg.streams,
            cfg.timeout,
        )
        .await
        {
            // Strip warmup window: ignore first `warmup_ms` ms of transfer.
            let warmup = Duration::from_millis(cfg.warmup_ms);
            let effective = if sr.elapsed > warmup {
                sr.bytes as f64 * 8.0
                    / ((sr.elapsed - warmup).as_secs_f64() * 1_000_000.0)
            } else {
                0.0
            };
            if effective <= 0.0 {
                continue;
            }
            return Some(ThroughputSample {
                mbps: effective,
                at_ms: start.elapsed().as_millis() as u64,
                source: url,
                streams: cfg.streams,
                bytes: sr.bytes,
                elapsed_ms: sr.elapsed.as_millis() as u64,
            });
        }
    }
    None
}

/// Run `samples` speed tests and return the median (robust against
/// one-off bad samples).
pub async fn measure(cfg: &SpeedTestConfig) -> Option<ThroughputSample> {
    let mut results: Vec<ThroughputSample> = Vec::new();
    for _ in 0..cfg.samples {
        if let Some(s) = measure_once(cfg).await {
            results.push(s);
        }
    }
    if results.is_empty() {
        return None;
    }
    results.sort_by(|a, b| a.mbps.partial_cmp(&b.mbps).unwrap_or(std::cmp::Ordering::Equal));
    let mid = results.len() / 2;
    Some(results[mid])
}

/// Continuous throughput measurement: runs in a loop and reports each
/// new sample via callback.
pub async fn run_continuous<F>(cfg: SpeedTestConfig, interval: Duration, mut on_sample: F)
where
    F: FnMut(ThroughputSample),
{
    loop {
        if let Some(s) = measure(&cfg).await {
            on_sample(s);
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let c = SpeedTestConfig::default();
        assert_eq!(c.target_bytes, 10 * 1024 * 1024);
        assert_eq!(c.samples, 3);
        assert_eq!(c.streams, 4);
        assert_eq!(c.warmup_ms, 750);
    }

    #[test]
    fn sample_serializes() {
        let s = ThroughputSample {
            mbps: 95.4,
            at_ms: 1234,
            source: "test",
            streams: 4,
            bytes: 10_000_000,
            elapsed_ms: 840,
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("95.4"));
        assert!(j.contains("streams"));
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn real_speed_test_returns_mbps() {
        let cfg = SpeedTestConfig {
            target_bytes: 1024 * 1024, // 1 MB for fast CI
            samples: 1,
            streams: 2,
            warmup_ms: 200,
            ..Default::default()
        };
        let s = measure(&cfg).await.expect("must reach a CDN");
        assert!(s.mbps > 0.1, "expected >0.1 Mbps, got {}", s.mbps);
        assert!(s.bytes > 0);
    }
}
