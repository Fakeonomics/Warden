use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::mind::{BlockReason, GeoBlockSignal, TrafficWatchdog};

#[derive(Debug, Clone)]
pub enum ProbeTarget {
    HttpGet {
        url: String,
    },
    Head {
        url: String,
    },
    Custom {
        host: String,
        port: u16,
        path: String,
    },
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub target: ProbeTarget,
    pub host: String,
    pub status: u16,
    pub body: String,
    pub elapsed: Duration,
    pub at: Instant,
}

impl ProbeResult {
    pub fn to_signal(&self) -> GeoBlockSignal {
        GeoBlockSignal {
            host: self.host.clone(),
            status: self.status,
            body_excerpt: self.body.chars().take(200).collect(),
            detected_at: self.at,
            reason: BlockReason::classify(self.status, &self.body),
        }
    }
}

pub struct TrafficMonitor {
    pub watchdog: Arc<Mutex<TrafficWatchdog>>,
    pub targets: Mutex<Vec<ProbeTarget>>,
    pub last_results: Mutex<VecDeque<ProbeResult>>,
    pub max_results: usize,
}

impl TrafficMonitor {
    pub fn new() -> Self {
        TrafficMonitor {
            watchdog: Arc::new(Mutex::new(TrafficWatchdog::new())),
            targets: Mutex::new(Vec::new()),
            last_results: Mutex::new(VecDeque::new()),
            max_results: 32,
        }
    }

    pub async fn add_target(&self, target: ProbeTarget) {
        self.targets.lock().await.push(target);
    }

    pub async fn add_default_targets(&self) {
        let defaults = [
            ProbeTarget::HttpGet {
                url: "https://www.google.com/".into(),
            },
            ProbeTarget::HttpGet {
                url: "https://www.youtube.com/".into(),
            },
            ProbeTarget::HttpGet {
                url: "https://www.netflix.com/".into(),
            },
            ProbeTarget::HttpGet {
                url: "https://www.spotify.com/".into(),
            },
        ];
        for t in defaults {
            self.add_target(t).await;
        }
    }

    pub async fn enable(&self) {
        let mut wd = self.watchdog.lock().await;
        wd.enable();
        info!(
            "traffic watchdog: ON (interval={}s)",
            wd.poll_interval.as_secs()
        );
    }

    pub async fn disable(&self) {
        let mut wd = self.watchdog.lock().await;
        wd.disable();
        info!("traffic watchdog: OFF");
    }

    pub async fn is_enabled(&self) -> bool {
        self.watchdog.lock().await.enabled
    }

    pub async fn probe_once(&self) -> Vec<ProbeResult> {
        let targets = self.targets.lock().await.clone();
        let mut out = Vec::new();
        for target in targets {
            match Self::probe(target.clone()).await {
                Ok(r) => {
                    out.push(r.clone());
                    if self.is_enabled().await {
                        let signal = r.to_signal();
                        if signal.reason != BlockReason::Unknown {
                            warn!(
                                "geo-block signal: host={} status={} reason={:?}",
                                signal.host, signal.status, signal.reason
                            );
                        }
                        self.watchdog.lock().await.record(signal);
                    }
                }
                Err(e) => {
                    debug!("probe error: {:?} -> {}", target, e);
                }
            }
        }
        let mut last = self.last_results.lock().await;
        for r in out.iter() {
            if last.len() >= self.max_results {
                last.pop_front();
            }
            last.push_back(r.clone());
        }
        out
    }

    pub async fn run_loop(&self) {
        loop {
            if !self.is_enabled().await {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let interval = self.watchdog.lock().await.poll_interval;
            let _ = self.probe_once().await;
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn should_evade(&self) -> bool {
        self.watchdog.lock().await.should_evade()
    }

    pub async fn recent_reason(&self) -> Option<BlockReason> {
        self.watchdog.lock().await.recent_reason()
    }

    pub async fn probe(target: ProbeTarget) -> anyhow::Result<ProbeResult> {
        let start = Instant::now();
        let (url, host) = match &target {
            ProbeTarget::HttpGet { url } | ProbeTarget::Head { url } => {
                let u = url.clone();
                let h = url::Url::parse(url)
                    .ok()
                    .and_then(|p| p.host_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown".into());
                (u, h)
            }
            ProbeTarget::Custom { host, .. } => (format!("http://{}:{}/", host, 80), host.clone()),
        };
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .user_agent("Mozilla/5.0 Warden/0.1")
            .build()?;
        let method = match &target {
            ProbeTarget::Head { .. } => client.head(&url),
            _ => client.get(&url),
        };
        let resp = method.send().await?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Ok(ProbeResult {
            target,
            host,
            status,
            body,
            elapsed: start.elapsed(),
            at: start,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watchdog_toggle_changes_recording() {
        let m = TrafficMonitor::new();
        m.add_default_targets().await;
        m.enable().await;
        assert!(m.is_enabled().await);
        m.disable().await;
        assert!(!m.is_enabled().await);
    }
}
