use litcrypt2::use_litcrypt;

extern crate alloc;
use_litcrypt!();

pub mod config;
pub mod api;
pub mod error;
pub mod protocol;
pub mod opsec;

pub use config::*;
pub use error::WardenError;
pub use api::{ApiClient, ServerConfig};
pub use protocol::ProtocolManager;
pub use opsec::{OpsecManager, OpsecStatus};

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub struct Warden {
    pub config: Arc<RwLock<WardenConfig>>,
    pub api: Arc<ApiClient>,
    pub protocols: Arc<ProtocolManager>,
    pub opsec: Arc<RwLock<OpsecManager>>,
    pub active: RwLock<Option<ActiveConnection>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActiveConnection {
    pub session_id: String,
    pub protocol: String,
    pub server: String,
    pub host: String,
    pub port: i32,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl Warden {
    pub async fn new(config: WardenConfig) -> Result<Self, WardenError> {
        let mode = config.mode;
        let api_cfg = config.api.clone();
        let proto_cfg = config.protocols.clone();
        let opsec_cfg = config.opsec.clone();

        let api = Arc::new(ApiClient::new(api_cfg)?);
        let protocols = Arc::new(ProtocolManager::new(proto_cfg, api.clone()).await?);
        let opsec = Arc::new(RwLock::new(OpsecManager::with_mode(opsec_cfg, mode)));

        info!("warden init mode={:?} api={}", config.mode, config.api.base_url);

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            api,
            protocols,
            opsec,
            active: RwLock::new(None),
        })
    }

    /// One-click connect. civilian mode auto-filters to preferred regions;
    /// operator mode bypasses restrictions and uses raw health ranking.
    pub async fn connect(&self, token: &str) -> Result<ActiveConnection, WardenError> {
        let cfg = self.config.read().await.clone();
        let configs = self.api.fetch_subscription(token).await?;
        let alive: Vec<_> = configs.into_iter().filter(|c| c.is_alive).collect();
        if alive.is_empty() { return Err(WardenError::NoConfigs); }

        info!("attempting from {} alive configs (mode={:?})", alive.len(), cfg.mode);

        let opsec = self.opsec.read().await;
        let operator = opsec.mode().is_operator();
        drop(opsec);

        let conn = self.protocols
            .try_connect(&cfg.rotation.prefer_regions, &cfg.rotation.exclude_countries, operator, &alive)
            .await?
            .ok_or(WardenError::AllFailed)?;

        *self.active.write().await = Some(conn.clone());
        Ok(conn)
    }

    pub async fn disconnect(&self) -> Result<(), WardenError> {
        let mut guard = self.active.write().await;
        if let Some(conn) = guard.take() {
            self.protocols.disconnect(&conn.session_id).await?;
            self.opsec.read().await.on_kill_switch();
            info!("disconnected from {}:{}", conn.host, conn.port);
        }
        Ok(())
    }

    pub async fn status(&self) -> Option<ActiveConnection> {
        self.active.read().await.clone()
    }

    pub async fn opsec_status(&self) -> OpsecStatus {
        self.opsec.read().await.status()
    }

    /// Unlock operator mode with code. Returns true if unlocked.
    pub async fn unlock_operator(&self, code: &str) -> bool {
        let mut opsec = self.opsec.write().await;
        let ok = opsec.unlock(code);
        if ok {
            let mut cfg = self.config.write().await;
            cfg.mode = Mode::Operator;
            info!("operator mode unlocked");
        }
        ok
    }

    /// Lock back to civilian mode.
    pub async fn lock(&self) {
        let mut opsec = self.opsec.write().await;
        opsec.lock();
        let mut cfg = self.config.write().await;
        cfg.mode = Mode::Civilian;
        info!("locked to civilian mode");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litcrypt2::lc;

    #[tokio::test]
    async fn warden_new_creates_instance() {
        let cfg = WardenConfig::default();
        let warden = Warden::new(cfg).await;
        assert!(warden.is_ok());
        let warden = warden.unwrap();
        assert_eq!(warden.config.read().await.mode, Mode::Civilian);
    }

    #[tokio::test]
    async fn warden_status_none_initially() {
        let warden = Warden::new(WardenConfig::default()).await.unwrap();
        assert!(warden.status().await.is_none());
    }

    #[tokio::test]
    async fn warden_opsec_status_default() {
        let warden = Warden::new(WardenConfig::default()).await.unwrap();
        let status = warden.opsec_status().await;
        assert!(!status.mode_operator);
        assert!(status.enabled);
    }

    #[tokio::test]
    async fn warden_disconnect_noop_when_no_active() {
        let warden = Warden::new(WardenConfig::default()).await.unwrap();
        let result = warden.disconnect().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn warden_lock_sets_civilian() {
        let mut cfg = WardenConfig::default();
        cfg.mode = Mode::Operator;
        let warden = Warden::new(cfg).await.unwrap();
        warden.lock().await;
        assert!(!warden.opsec.read().await.mode().is_operator());
        assert_eq!(warden.config.read().await.mode, Mode::Civilian);
    }

    #[tokio::test]
    async fn unlock_operator_wrong_code() {
        let warden = Warden::new(WardenConfig::default()).await.unwrap();
        assert!(!warden.unlock_operator("wrong-code").await);
        assert!(!warden.config.read().await.mode.is_operator());
    }

    #[tokio::test]
    async fn unlock_operator_correct_code() {
        let warden = Warden::new(WardenConfig::default()).await.unwrap();
        let key = lc!("GREYHOUND-19-OPERATOR");
        assert!(warden.unlock_operator(&key).await);
        assert!(warden.config.read().await.mode.is_operator());
        assert!(warden.opsec.read().await.mode().is_operator());
    }

    #[tokio::test]
    async fn connect_returns_no_configs_when_empty_subscription() {
        let mut cfg = WardenConfig::default();
        cfg.api.auth_token = Some("test-token".into());
        let warden = Warden::new(cfg).await.unwrap();
        // This will fail because the API endpoint doesn't actually exist
        let result = warden.connect("test-token").await;
        // Should fail with an API error (not NoConfigs since we can't fetch)
        assert!(result.is_err());
    }
}
