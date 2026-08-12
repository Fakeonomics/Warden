pub mod config;
pub mod api;
pub mod protocol;
pub mod opsec;
pub mod error;

pub use config::*;
pub use error::WardenError;
pub use api::{ApiClient, ServerConfig};
pub use protocol::ProtocolManager;
pub use opsec::OpsecManager;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub struct Warden {
    pub config: Arc<WardenConfig>,
    pub api: Arc<ApiClient>,
    pub protocols: Arc<ProtocolManager>,
    pub opsec: Arc<OpsecManager>,
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
        let api = Arc::new(ApiClient::new(config.api.clone())?);
        let protocols = Arc::new(ProtocolManager::new(config.protocols.clone(), api.clone()).await?);
        let opsec = Arc::new(OpsecManager::new(config.opsec.clone()));

        info!("Warden initialized: api={}, protocols={:?}, opsec={}",
            config.api.base_url, config.protocols.preferred, config.opsec.enabled);

        Ok(Self {
            config: Arc::new(config),
            api,
            protocols,
            opsec,
            active: RwLock::new(None),
        })
    }

    pub async fn connect_best(&self, token: &str) -> Result<ActiveConnection, WardenError> {
        let configs = self.api.fetch_subscription(token).await?;
        let alive: Vec<_> = configs.into_iter().filter(|c| c.is_alive).collect();
        if alive.is_empty() {
            return Err(WardenError::NoConfigs);
        }

        info!("Attempting connection from {} alive configs", alive.len());

        for proto in &self.config.protocols.preferred {
            if let Some(conn) = self.protocols.try_connect(proto, &alive).await? {
                info!("Connected via {} to {}:{}", proto, conn.host, conn.port);
                let mut guard = self.active.write().await;
                *guard = Some(conn.clone());
                return Ok(conn);
            }
        }
        Err(WardenError::AllFailed)
    }

    pub async fn disconnect(&self) -> Result<(), WardenError> {
        let mut guard = self.active.write().await;
        if let Some(conn) = guard.take() {
            self.protocols.disconnect(&conn.session_id).await?;
            info!("Disconnected from {}:{}", conn.host, conn.port);
        }
        Ok(())
    }

    pub async fn status(&self) -> Option<ActiveConnection> {
        self.active.read().await.clone()
    }
}
