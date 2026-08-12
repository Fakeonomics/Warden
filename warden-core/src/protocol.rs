use litcrypt2::lc;
use crate::{config::{ProtocolsConfig, OpsecConfig}, error::WardenError, api::ServerConfig};
use crate::ActiveConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use chrono::Utc;

lc!();

pub struct ProtocolManager {
    config: ProtocolsConfig,
    api: Arc<crate::api::ApiClient>,
    sessions: RwLock<HashMap<String, SessionHandle>>,
}

#[derive(Debug, Clone)]
struct SessionHandle {
    id: String,
    protocol: String,
    host: String,
    port: i32,
    started_at: chrono::DateTime<Utc>,
    fingerprint: String,
}

impl ProtocolManager {
    pub async fn new(config: ProtocolsConfig, api: Arc<crate::api::ApiClient>) -> Result<Self, WardenError> {
        Ok(Self { config, api, sessions: RwLock::new(HashMap::new()) })
    }

    /// Pick best alive config per preferred protocol order. Excludes countries in
    /// `exclude` and prefers those in `prefer`. Operator mode bypasses region filter.
    pub async fn try_connect(&self, prefer: &[String], exclude: &[String], operator: bool, configs: &[ServerConfig]) -> Result<Option<ActiveConnection>, WardenError> {
        for proto in &self.config.preferred {
            if !enabled_for(&self.config, proto) { continue; }
            let mut ranked: Vec<&ServerConfig> = configs.iter()
                .filter(|c| c.is_alive && &c.protocol == proto)
                .collect();

            if !operator {
                ranked.retain(|c| {
                    let r = c.region.as_deref().unwrap_or("");
                    !exclude.iter().any(|e| e.eq_ignore_ascii_case(r))
                });
                ranked.sort_by_key(|c| {
                    let score = c.health_score.unwrap_or(0.5);
                    let in_preferred = c.region.as_deref()
                        .map(|r| prefer.iter().position(|p| p.eq_ignore_ascii_case(r)).unwrap_or(99))
                        .unwrap_or(98);
                    std::cmp::Reverse((score * 1000.0) as i64 - in_preferred as i64)
                });
            } else {
                ranked.sort_by(|a, b| {
                    b.health_score.unwrap_or(0.5).partial_cmp(&a.health_score.unwrap_or(0.5)).unwrap()
                });
            }

            for cfg in ranked.iter().take(5) {
                match self.open_session(proto, cfg).await {
                    Ok(conn) => {
                        let sid = conn.session_id.clone();
                        self.sessions.write().await.insert(sid.clone(), SessionHandle {
                            id: sid, protocol: proto.clone(),
                            host: conn.host.clone(), port: conn.port, started_at: conn.connected_at,
                            fingerprint: conn.protocol.clone(),
                        });
                        return Ok(Some(conn));
                    }
                    Err(e) => warn!("{} -> {}:{} failed: {:?}", proto, cfg.host, cfg.port, e),
                }
            }
        }
        Ok(None)
    }

    async fn open_session(&self, proto: &str, cfg: &ServerConfig) -> Result<ActiveConnection, WardenError> {
        let _ = url::Url::parse(&cfg.config_line)?;
        let sid = Uuid::new_v4().to_string();
        let now = Utc::now();
        info!("open {} {}:{} sid={}", proto, cfg.host, cfg.port, &sid[..8]);
        // Phase 2: handoff to boringtun / shadowsocks / quinn runtime.
        Ok(ActiveConnection {
            session_id: sid,
            protocol: proto.into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    pub async fn disconnect(&self, session_id: &str) -> Result<(), WardenError> {
        self.sessions.write().await.remove(session_id);
        Ok(())
    }

    pub async fn list(&self) -> Vec<String> {
        self.sessions.read().await.keys().cloned().collect()
    }
}

fn enabled_for(c: &ProtocolsConfig, p: &str) -> bool {
    match p {
        s if s == "wireguard" => c.wireguard_enabled,
        s if s == "vless" => c.vless_enabled,
        s if s == "shadowsocks" => c.shadowsocks_enabled,
        s if s == "hysteria2" => c.hysteria2_enabled,
        _ => false,
    }
}
