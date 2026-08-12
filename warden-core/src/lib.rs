use litcrypt2::{lc, use_litcrypt};

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

lc!();

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
