use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::api::ServerConfig;
use crate::error::WardenError;
use crate::protocol_helpers::{Hy2Params, SsParams, TrojanParams, VlessParams, VmessParams};

pub const PROBE_TARGETS: &[&str] = &[
    "http://www.google.com/generate_204",
    "http://www.youtube.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    Alive,
    Dead,
    Uncertain,
}

#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub config: ServerConfig,
    pub verdict: ProbeVerdict,
    pub latency_ms: Option<u64>,
    pub target: &'static str,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub checked_at: Instant,
}

#[derive(Debug, Clone)]
pub struct LiveProbeStats {
    pub total: usize,
    pub tested: usize,
    pub alive: usize,
    pub dead: usize,
    pub current_target: Option<String>,
    pub started_at: Instant,
    pub last_latency_ms: Option<u64>,
}

impl LiveProbeStats {
    pub fn progress(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        self.tested as f64 / self.total as f64
    }
}

pub async fn probe_via_vless(
    params: VlessParams,
    target_host: &str,
    target_path: &str,
) -> Result<u64, WardenError> {
    use uuid::Uuid;
    let server_addr = format!("{}:{}", params.host, params.port)
        .parse::<std::net::SocketAddr>()
        .map_err(|e| WardenError::TunnelError(e.to_string()))?;
    let start = Instant::now();
    let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
        .await
        .map_err(|_| WardenError::TunnelError("vless probe connect timed out".into()))?
        .map_err(|e| WardenError::TunnelError(format!("vless probe: {}", e)))?;

    let mut req: Vec<u8> = Vec::new();
    req.push(0x00);
    let uuid_bytes = Uuid::parse_str(&params.uuid)
        .map_err(|e| WardenError::TunnelError(format!("vless uuid: {}", e)))?
        .as_bytes()
        .to_vec();
    req.extend_from_slice(&uuid_bytes);
    req.push(0x00);
    req.push(0x01);
    let port_bytes: u16 = 80;
    req.extend_from_slice(&port_bytes.to_be_bytes());
    req.push(0x02);
    req.push(target_host.len() as u8);
    req.extend_from_slice(target_host.as_bytes());
    // empty headers

    let http = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_path, target_host
    );
    req.extend_from_slice(http.as_bytes());

    tcp.write_all(&req)
        .await
        .map_err(|e| WardenError::TunnelError(format!("vless probe write: {}", e)))?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .map_err(|_| WardenError::TunnelError("vless probe read timed out".into()))?
        .map_err(|e| WardenError::TunnelError(format!("vless probe read: {}", e)))?;
    let text = String::from_utf8_lossy(&buf[..n]);
    if text.contains("HTTP/1.1 2") || text.contains("HTTP/1.0 2") || text.contains("204") {
        Ok(start.elapsed().as_millis() as u64)
    } else {
        Err(WardenError::TunnelError(format!(
            "vless probe: unexpected reply: {}",
            &text.chars().take(120).collect::<String>()
        )))
    }
}

pub async fn probe_via_trojan(
    params: TrojanParams,
    target_host: &str,
    target_path: &str,
) -> Result<u64, WardenError> {
    use sha2::{Digest, Sha224};
    let server_addr = format!("{}:{}", params.host, params.port)
        .parse::<std::net::SocketAddr>()
        .map_err(|e| WardenError::TunnelError(e.to_string()))?;
    let start = Instant::now();
    let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
        .await
        .map_err(|_| WardenError::TunnelError("trojan probe connect timed out".into()))?
        .map_err(|e| WardenError::TunnelError(format!("trojan probe: {}", e)))?;

    let mut hasher = Sha224::new();
    hasher.update(params.password.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let mut handshake = Vec::new();
    handshake.extend_from_slice(hash.as_bytes());
    handshake.extend_from_slice(b"\r\n");
    let http = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        target_path, target_host
    );
    handshake.extend_from_slice(http.as_bytes());

    tcp.write_all(&handshake)
        .await
        .map_err(|e| WardenError::TunnelError(format!("trojan probe: {}", e)))?;

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
        .await
        .map_err(|_| WardenError::TunnelError("trojan probe read timed out".into()))?
        .map_err(|e| WardenError::TunnelError(format!("trojan probe read: {}", e)))?;
    let text = String::from_utf8_lossy(&buf[..n]);
    if text.contains("HTTP/1.") {
        Ok(start.elapsed().as_millis() as u64)
    } else {
        Err(WardenError::TunnelError(format!(
            "trojan probe: invalid reply: {}",
            &text.chars().take(120).collect::<String>()
        )))
    }
}

pub async fn probe_via_ss(
    _params: SsParams,
    _target_host: &str,
    _target_path: &str,
) -> Result<u64, WardenError> {
    Err(WardenError::TunnelError(
        "ss probe: not implemented in build".into(),
    ))
}

pub async fn probe_via_vmess(
    _params: VmessParams,
    _target_host: &str,
    _target_path: &str,
) -> Result<u64, WardenError> {
    Err(WardenError::TunnelError(
        "vmess probe: not implemented in build".into(),
    ))
}

pub async fn probe_via_hy2(
    _params: Hy2Params,
    _target_host: &str,
    _target_path: &str,
) -> Result<u64, WardenError> {
    Err(WardenError::TunnelError(
        "hy2 probe: not implemented in build".into(),
    ))
}

pub async fn probe_config(cfg: &ServerConfig) -> ProbeReport {
    let (host, path) = (PROBE_TARGETS[0], "/generate_204");
    let start = Instant::now();
    let result: Result<u64, WardenError> = match cfg.protocol.as_str() {
        "vless" => match VlessParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port) {
            Ok(p) => probe_via_vless(p, host, path).await,
            Err(e) => Err(e),
        },
        "trojan" => match TrojanParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port) {
            Ok(p) => probe_via_trojan(p, host, path).await,
            Err(e) => Err(e),
        },
        "ss" | "shadowsocks" => {
            match SsParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port) {
                Ok(p) => probe_via_ss(p, host, path).await,
                Err(e) => Err(e),
            }
        }
        "vmess" => match VmessParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port) {
            Ok(p) => probe_via_vmess(p, host, path).await,
            Err(e) => Err(e),
        },
        "hysteria2" | "hy2" => {
            match Hy2Params::from_config_line(&cfg.config_line, &cfg.host, cfg.port) {
                Ok(p) => probe_via_hy2(p, host, path).await,
                Err(e) => Err(e),
            }
        }
        other => Err(WardenError::ProtocolNotSupported(other.to_string())),
    };

    let elapsed_ms = start.elapsed().as_millis() as u64;
    match result {
        Ok(latency) => {
            info!(
                "live probe OK: {}:{} via {} ({}ms)",
                cfg.host, cfg.port, cfg.protocol, latency
            );
            ProbeReport {
                config: cfg.clone(),
                verdict: ProbeVerdict::Alive,
                latency_ms: Some(latency),
                target: PROBE_TARGETS[0],
                status: Some(204),
                error: None,
                checked_at: Instant::now(),
            }
        }
        Err(e) => {
            debug!(
                "live probe DEAD: {}:{} via {} ({}ms): {}",
                cfg.host, cfg.port, cfg.protocol, elapsed_ms, e
            );
            ProbeReport {
                config: cfg.clone(),
                verdict: ProbeVerdict::Dead,
                latency_ms: Some(elapsed_ms),
                target: PROBE_TARGETS[0],
                status: None,
                error: Some(e.to_string()),
                checked_at: Instant::now(),
            }
        }
    }
}

pub async fn find_first_alive(
    configs: Vec<ServerConfig>,
    max_attempts: usize,
) -> (Option<ServerConfig>, LiveProbeStats) {
    let started_at = Instant::now();
    let total = max_attempts.min(configs.len());
    let mut tested = 0usize;
    let mut alive = 0usize;
    let mut dead = 0usize;
    let mut last_latency = None;

    for cfg in configs.into_iter().take(total) {
        tested += 1;
        let report = probe_config(&cfg).await;
        last_latency = report.latency_ms;
        match report.verdict {
            ProbeVerdict::Alive => {
                alive += 1;
                let stats = LiveProbeStats {
                    total,
                    tested,
                    alive,
                    dead,
                    current_target: Some(format!("{}:{}", cfg.host, cfg.port)),
                    started_at,
                    last_latency_ms: last_latency,
                };
                return (Some(cfg), stats);
            }
            _ => {
                dead += 1;
            }
        }
    }
    let stats = LiveProbeStats {
        total,
        tested,
        alive,
        dead,
        current_target: None,
        started_at,
        last_latency_ms: last_latency,
    };
    (None, stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::ServerConfig;

    fn mkcfg(protocol: &str, host: &str) -> ServerConfig {
        ServerConfig {
            id: 1,
            config_line: format!("{}://dead@{}:443", protocol, host),
            protocol: protocol.into(),
            host: host.into(),
            port: 443,
            is_alive: true,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        }
    }

    #[tokio::test]
    async fn probe_dead_vless_returns_dead() {
        let cfg = mkcfg("vless", "0.0.0.0");
        let report = probe_config(&cfg).await;
        assert_eq!(report.verdict, ProbeVerdict::Dead);
    }

    #[test]
    fn progress_zero_when_empty() {
        let stats = LiveProbeStats {
            total: 0,
            tested: 0,
            alive: 0,
            dead: 0,
            current_target: None,
            started_at: Instant::now(),
            last_latency_ms: None,
        };
        assert_eq!(stats.progress(), 0.0);
    }
}
