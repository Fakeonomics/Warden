use crate::{config::ProtocolsConfig, error::WardenError, api::ServerConfig};
use crate::ActiveConnection;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;
use chrono::Utc;

pub struct ProtocolManager {
    config: ProtocolsConfig,
    api: Arc<crate::api::ApiClient>,
    sessions: RwLock<HashMap<String, SessionInfo>>,
}

#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub protocol: String,
    pub host: String,
    pub port: i32,
    pub started_at: chrono::DateTime<Utc>,
}

impl ProtocolManager {
    pub async fn new(config: ProtocolsConfig, api: Arc<crate::api::ApiClient>) -> Result<Self, WardenError> {
        Ok(Self {
            config,
            api,
            sessions: RwLock::new(HashMap::new()),
        })
    }

    pub async fn try_connect(&self, protocol: &str, configs: &[ServerConfig]) -> Result<Option<ActiveConnection>, WardenError> {
        let enabled = match protocol {
            "wireguard" => self.config.wireguard_enabled,
            "vless" => self.config.vless_enabled,
            "shadowsocks" => self.config.shadowsocks_enabled,
            "hysteria2" => self.config.hysteria2_enabled,
            _ => false,
        };
        if !enabled {
            return Ok(None);
        }

        // configs preferring our preferred regions
        let mut ranked: Vec<&ServerConfig> = configs.iter()
            .filter(|c| c.protocol == protocol && c.is_alive)
            .collect();
        ranked.sort_by(|a, b| {
            b.health_score.unwrap_or(0.5).partial_cmp(&a.health_score.unwrap_or(0.5)).unwrap()
        });

        for cfg in ranked.iter().take(5) {
            match self.open_session(protocol, cfg).await {
                Ok(conn) => {
                    let sid = conn.session_id.clone();
                    self.sessions.write().await.insert(sid.clone(), SessionInfo {
                        id: sid, protocol: protocol.into(),
                        host: conn.host.clone(), port: conn.port, started_at: conn.connected_at,
                    });
                    return Ok(Some(conn));
                }
                Err(e) => warn!("Failed {} to {}:{} - {:?}", protocol, cfg.host, cfg.port, e),
            }
        }
        Ok(None)
    }

    async fn open_session(&self, protocol: &str, cfg: &ServerConfig) -> Result<ActiveConnection, WardenError> {
        // Validation: parse config_line using url crate (covered)
        let _ = url::Url::parse(&cfg.config_line)?;
        let sid = Uuid::new_v4().to_string();
        let now = Utc::now();
        info!("Opening {} session to {}:{} (sid={})", protocol, cfg.host, cfg.port, &sid[..8]);

        // Phase 2 will hand off to boringtun/shadowsocks/quinn runtime here.
        // For MVP we record the session; a real network handshake requires admin/root + TUN.

        Ok(ActiveConnection {
            session_id: sid,
            protocol: protocol.into(),
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
}
