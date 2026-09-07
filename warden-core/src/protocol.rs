use crate::{config::ProtocolsConfig, error::WardenError, api::ServerConfig};
use crate::ActiveConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use chrono::Utc;

pub struct ProtocolManager {
    config: ProtocolsConfig,
    #[allow(dead_code)]
    api: Arc<crate::api::ApiClient>,
    sessions: RwLock<HashMap<String, SessionHandle>>,
}

#[derive(Debug, Clone)]
struct SessionHandle {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    protocol: String,
    #[allow(dead_code)]
    host: String,
    #[allow(dead_code)]
    port: i32,
    #[allow(dead_code)]
    started_at: chrono::DateTime<Utc>,
    #[allow(dead_code)]
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
        "wireguard" => c.wireguard_enabled,
        "vless" => c.vless_enabled,
        "shadowsocks" => c.shadowsocks_enabled,
        "hysteria2" => c.hysteria2_enabled,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ApiClient, ApiConfig};
    use litcrypt2::lc;

    fn make_cfg(proto: &str, region: &str, score: f64, port: i32) -> ServerConfig {
        let host = format!("{}.example.com", region.to_lowercase());
        let url = format!("{}://user@{}:{}/?#{}", proto, host, port, region);
        ServerConfig {
            id: 1,
            config_line: url,
            protocol: proto.to_string(),
            host,
            port,
            is_alive: true,
            source: None,
            health_score: Some(score),
            response_time_ms: Some(100),
            region: Some(region.to_string()),
        }
    }

    #[tokio::test]
    async fn try_connect_picks_vless_first() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs = vec![
            make_cfg("wireguard", "DE", 0.9, 51820),
            make_cfg("vless", "DE", 0.9, 443),
        ];
        let prefer: Vec<String> = vec!["DE".into()];
        let exclude: Vec<String> = vec![];

        let conn = mgr.try_connect(&prefer, &exclude, false, &configs).await.unwrap();
        assert!(conn.is_some());
        assert_eq!(conn.unwrap().protocol, "vless");
    }

    #[tokio::test]
    async fn try_connect_excludes_country_civilian() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs = vec![
            make_cfg("vless", "CN", 1.0, 443),
            make_cfg("vless", "DE", 0.8, 443),
        ];
        let prefer: Vec<String> = vec![];
        let exclude: Vec<String> = vec!["CN".into()];

        let conn = mgr.try_connect(&prefer, &exclude, false, &configs).await.unwrap();
        assert!(conn.is_some());
        assert_eq!(conn.unwrap().host, "de.example.com");
    }

    #[tokio::test]
    async fn try_connect_operator_bypasses_exclude() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs = vec![
            make_cfg("vless", "CN", 1.0, 443),
            make_cfg("vless", "DE", 0.8, 443),
        ];
        let prefer: Vec<String> = vec![];
        let exclude: Vec<String> = vec!["CN".into()];

        let conn = mgr.try_connect(&prefer, &exclude, true, &configs).await.unwrap();
        assert!(conn.is_some());
        // operator mode sorts by health score, CN has 1.0 > DE's 0.8
        assert_eq!(conn.unwrap().host, "cn.example.com");
    }

    #[tokio::test]
    async fn try_connect_no_alive_configs() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs: Vec<ServerConfig> = vec![];
        let conn = mgr.try_connect(&[], &[], false, &configs).await.unwrap();
        assert!(conn.is_none());
    }

    #[tokio::test]
    async fn try_connect_dead_configs_only() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let mut dead = make_cfg("vless", "DE", 0.5, 443);
        dead.is_alive = false;
        let configs = vec![dead];

        let conn = mgr.try_connect(&[], &[], false, &configs).await.unwrap();
        assert!(conn.is_none());
    }

    #[tokio::test]
    async fn try_connect_disabled_protocol_skipped() {
        let cfg = ProtocolsConfig {
            preferred: vec!["wireguard".into(), "vless".into()],
            wireguard_enabled: false,
            vless_enabled: true,
            shadowsocks_enabled: true,
            hysteria2_enabled: true,
        };
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let wg = make_cfg("wireguard", "DE", 1.0, 51820);
        let vless = make_cfg("vless", "DE", 0.8, 443);
        let configs = vec![wg, vless];

        let conn = mgr.try_connect(&[], &[], false, &configs).await.unwrap();
        assert_eq!(conn.unwrap().protocol, "vless");
    }

    #[tokio::test]
    async fn try_connect_prefs_preferred_region() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        // Same score, but DE is in preferred regions -> DE should rank higher
        let configs = vec![
            make_cfg("vless", "FR", 0.5, 443),
            make_cfg("vless", "DE", 0.5, 443),
        ];
        let prefer: Vec<String> = vec!["DE".into(), "FR".into()];
        let exclude: Vec<String> = vec![];

        let conn = mgr.try_connect(&prefer, &exclude, false, &configs).await.unwrap();
        assert_eq!(conn.unwrap().host, "de.example.com");
    }

    #[tokio::test]
    async fn disconnect_removes_session() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs = vec![make_cfg("vless", "DE", 0.9, 443)];
        let conn = mgr.try_connect(&[], &[], false, &configs).await.unwrap().unwrap();

        assert_eq!(mgr.list().await.len(), 1);
        mgr.disconnect(&conn.session_id).await.unwrap();
        assert_eq!(mgr.list().await.len(), 0);
    }

    #[tokio::test]
    async fn disconnect_nonexistent_is_noop() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();
        mgr.disconnect("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn open_session_generates_session() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs = vec![make_cfg("vless", "DE", 0.9, 443)];
        let conn = mgr.try_connect(&[], &[], false, &configs).await.unwrap().unwrap();
        assert!(!conn.session_id.is_empty());
        assert_eq!(conn.protocol, "vless");
        assert_eq!(conn.host, "de.example.com");
        assert_eq!(conn.port, 443);
        assert_eq!(conn.server, "de.example.com:443");
        assert_eq!(conn.bytes_sent, 0);
        assert_eq!(conn.bytes_received, 0);
    }

    #[test]
    fn enabled_for_all_protocols() {
        let cfg = ProtocolsConfig::default();
        assert!(enabled_for(&cfg, "wireguard"));
        assert!(enabled_for(&cfg, "vless"));
        assert!(enabled_for(&cfg, "shadowsocks"));
        assert!(enabled_for(&cfg, "hysteria2"));
    }

    #[test]
    fn enabled_for_disabled_protocol() {
        let cfg = ProtocolsConfig {
            preferred: vec![],
            wireguard_enabled: false,
            vless_enabled: true,
            shadowsocks_enabled: false,
            hysteria2_enabled: true,
        };
        assert!(!enabled_for(&cfg, "wireguard"));
        assert!(enabled_for(&cfg, "vless"));
        assert!(!enabled_for(&cfg, "shadowsocks"));
        assert!(enabled_for(&cfg, "hysteria2"));
    }

    #[test]
    fn enabled_for_unknown_protocol() {
        let cfg = ProtocolsConfig::default();
        assert!(!enabled_for(&cfg, "unknown"));
        assert!(!enabled_for(&cfg, "openvpn"));
    }

    #[tokio::test]
    async fn list_empty_when_no_sessions() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();
        assert!(mgr.list().await.is_empty());
    }

    #[tokio::test]
    async fn connect_multiple_creates_sessions() {
        let cfg = ProtocolsConfig::default();
        let api = Arc::new(ApiClient::new(ApiConfig::default()).unwrap());
        let mgr = ProtocolManager::new(cfg, api).await.unwrap();

        let configs = vec![
            make_cfg("vless", "DE", 0.9, 443),
            make_cfg("wireguard", "US", 0.8, 51820),
        ];

        let conn1 = mgr.try_connect(&[], &[], false, &configs).await.unwrap().unwrap();
        assert_eq!(mgr.list().await.len(), 1);

        mgr.disconnect(&conn1.session_id).await.unwrap();
        assert_eq!(mgr.list().await.len(), 0);

        let _conn2 = mgr.try_connect(&[], &[], false, &configs).await.unwrap().unwrap();
        assert_eq!(mgr.list().await.len(), 1);
    }
}
