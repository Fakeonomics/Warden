use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::api::ServerConfig;
use crate::error::WardenError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QualityMetrics {
    pub latency_ms: f64,
    pub throughput_mbps: f64,
    pub handshake_ok: bool,
    pub dpi_resistance: bool,
    pub last_tested: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenEntry {
    pub id: String,
    pub metrics: QualityMetrics,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConfigScoreCache {
    pub entries: HashMap<String, ProvenEntry>,
}

impl ConfigScoreCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(txt) => match serde_json::from_str(&txt) {
                Ok(entries) => ConfigScoreCache { entries },
                Err(_) => ConfigScoreCache::new(),
            },
            Err(_) => ConfigScoreCache::new(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), WardenError> {
        let json = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&ProvenEntry> {
        self.entries.get(id)
    }

    pub fn put(&mut self, id: &str, m: QualityMetrics) {
        self.entries.insert(
            id.to_string(),
            ProvenEntry {
                id: id.to_string(),
                metrics: m,
            },
        );
    }

    pub fn cleanup_stale(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.entries
            .retain(|_, v| now.saturating_sub(v.metrics.last_tested) < 3600);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[async_trait]
pub trait Probe: Send + Sync {
    async fn probe(&self, cfg: &ServerConfig) -> QualityMetrics;
}

pub struct ParallelProbe {
    pub probe: Arc<dyn Probe + Send + Sync>,
    pub concurrency: usize,
    pub timeout: Duration,
}

impl ParallelProbe {
    pub async fn run(&self, configs: &[ServerConfig]) -> Vec<(String, QualityMetrics)> {
        use tokio::task::JoinSet;
        let mut set = JoinSet::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.concurrency));

        for cfg in configs {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let cfg = cfg.clone();
            let probe = Arc::clone(&self.probe);
            let timeout = self.timeout;
            set.spawn(async move {
                let _permit = permit;
                let result = tokio::time::timeout(timeout, probe.probe(&cfg)).await;
                let metrics = result.unwrap_or(QualityMetrics {
                    latency_ms: 9999.0,
                    throughput_mbps: 0.0,
                    handshake_ok: false,
                    dpi_resistance: false,
                    last_tested: 0,
                });
                (cfg.id.to_string(), metrics)
            });
        }

        let mut results = Vec::new();
        while let Some(res) = set.join_next().await {
            if let Ok((id, m)) = res {
                results.push((id, m));
            }
        }
        results
    }
}

pub struct MockProbe;

#[async_trait]
impl Probe for MockProbe {
    async fn probe(&self, cfg: &ServerConfig) -> QualityMetrics {
        let base = cfg.id.unsigned_abs();
        let latency = match cfg.protocol.as_str() {
            "wireguard" => 20.0 + (base % 30) as f64,
            "vless" => 50.0 + (base % 40) as f64,
            "shadowsocks" => 80.0 + (base % 50) as f64,
            "hysteria2" => 100.0 + (base % 60) as f64,
            _ => 150.0,
        };
        QualityMetrics {
            latency_ms: latency,
            throughput_mbps: match cfg.protocol.as_str() {
                "wireguard" => 800.0,
                "vless" => 500.0,
                "shadowsocks" => 300.0,
                "hysteria2" => 600.0,
                _ => 100.0,
            },
            handshake_ok: true,
            dpi_resistance: matches!(cfg.protocol.as_str(), "wireguard" | "vless"),
            last_tested: 0,
        }
    }
}

pub struct ConfigPool {
    pub configs: Vec<ServerConfig>,
    pub cache: ConfigScoreCache,
    pub probe: Arc<dyn Probe + Send + Sync>,
}

impl ConfigPool {
    pub fn new(
        configs: Vec<ServerConfig>,
        cache: ConfigScoreCache,
        probe: Arc<dyn Probe + Send + Sync>,
    ) -> Self {
        ConfigPool {
            configs,
            cache,
            probe,
        }
    }

    pub fn load_cache(path: &Path) -> ConfigScoreCache {
        ConfigScoreCache::load(path)
    }

    pub fn save_cache(&self, path: &Path) -> Result<(), WardenError> {
        self.cache.save(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerConfig;

    #[test]
    fn cache_roundtrip() {
        let dir = std::env::temp_dir().join("warden_pool_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("proven.json");
        let mut cache = ConfigScoreCache::new();
        cache.put(
            "mci-wg",
            QualityMetrics {
                latency_ms: 25.0,
                throughput_mbps: 900.0,
                handshake_ok: true,
                dpi_resistance: true,
                last_tested: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        );
        cache.save(&path).unwrap();
        let loaded = ConfigScoreCache::load(&path);
        let entry = loaded.get("mci-wg").unwrap();
        assert_eq!(entry.metrics.latency_ms, 25.0);
        assert!(entry.metrics.dpi_resistance);
        println!("[pool] cache_roundtrip: ProvenEntry{{mci-wg}} saved+loaded OK");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn parallel_probe_mock() {
        let configs: Vec<ServerConfig> = (0..5)
            .map(|i| ServerConfig {
                id: i as i64,
                config_line: String::new(),
                protocol: if i % 2 == 0 {
                    "wireguard".into()
                } else {
                    "vless".into()
                },
                host: format!("host-{}", i),
                port: 51820 + i,
                is_alive: true,
                source: None,
                health_score: Some(0.5),
                response_time_ms: None,
                region: Some("US".into()),
            })
            .collect();
        let probe = ParallelProbe {
            probe: Arc::new(MockProbe),
            concurrency: 5,
            timeout: Duration::from_secs(1),
        };
        let start = std::time::Instant::now();
        let results = probe.run(&configs).await;
        let elapsed = start.elapsed();
        assert_eq!(results.len(), 5);
        let mut sorted = results.clone();
        sorted.sort_by(|a, b| a.1.latency_ms.partial_cmp(&b.1.latency_ms).unwrap());
        let result_map = results
            .iter()
            .cloned()
            .collect::<std::collections::HashMap<_, _>>();
        for (id, m) in &sorted {
            assert!(result_map
                .get(id)
                .map(|r| r.latency_ms == m.latency_ms)
                .unwrap_or(false));
        }
        println!(
            "[pool] parallel probe: {} configs probed in {:?}, ranked by avg_latency",
            results.len(),
            elapsed
        );
    }

    #[test]
    fn stale_cleanup() {
        let mut cache = ConfigScoreCache::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        cache.put(
            "fresh",
            QualityMetrics {
                latency_ms: 10.0,
                throughput_mbps: 100.0,
                handshake_ok: true,
                dpi_resistance: true,
                last_tested: now,
            },
        );
        cache.put(
            "stale",
            QualityMetrics {
                latency_ms: 10.0,
                throughput_mbps: 100.0,
                handshake_ok: true,
                dpi_resistance: true,
                last_tested: now - 7200,
            },
        );
        cache.cleanup_stale();
        assert!(cache.get("fresh").is_some());
        assert!(cache.get("stale").is_none());
    }
}
