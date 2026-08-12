use warden_core::{config::*, models::*, error::*};
use warden_api::ApiClient;
use warden_proto::{ProtocolId, ProtocolCapabilities, HandshakeResult, SessionKeys, ProtocolTransport, ProtocolAdapter};
use warden_wireguard::WireGuardAdapter;
use warden_vless::VlessAdapter;
use warden_shadowsocks::ShadowsocksAdapter;
use warden_hysteria::HysteriaAdapter;
use warden_crypto::{KeyStore, KeyPurpose};
use boringtun::noise::Tunn;
use shadowsocks::relay::socks5::Address;
use quinn::{Endpoint, ClientConfig, ServerConfig};
use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};
use uuid::Uuid;
use chrono::Utc;

pub struct VpnManager {
    config: ProtocolsConfig,
    key_store: Arc<dyn KeyStore>,
    api_client: Arc<ApiClient>,
    adapters: HashMap<ProtocolId, Box<dyn ProtocolAdapter>>,
    active_session: RwLock<Option<ActiveSession>>,
    stats: RwLock<VpnStats>,
}

#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub session_id: Uuid,
    pub protocol: ProtocolId,
    pub config: ServerConfig,
    pub transport: Box<dyn ProtocolTransport>,
    pub started_at: chrono::DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Default)]
pub struct VpnStats {
    pub total_connections: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub current_protocol: Option<ProtocolId>,
    pub current_server: Option<String>,
    pub uptime_seconds: u64,
}

impl VpnManager {
    pub async fn new(
        config: ProtocolsConfig,
        key_store: Arc<dyn KeyStore>,
        api_client: Arc<ApiClient>,
    ) -> Result<Self, WardenError> {
        let mut adapters: HashMap<ProtocolId, Box<dyn ProtocolAdapter>> = HashMap::new();
        
        // Initialize WireGuard adapter
        if config.wireguard.enabled {
            let adapter = WireGuardAdapter::new(config.wireguard.clone(), key_store.clone()).await?;
            adapters.insert(ProtocolId::WireGuard, Box::new(adapter));
            info!("WireGuard adapter initialized");
        }
        
        // Initialize VLESS adapter
        if config.vless.enabled {
            let adapter = VlessAdapter::new(config.vless.clone(), key_store.clone()).await?;
            adapters.insert(ProtocolId::VLESS, Box::new(adapter));
            info!("VLESS adapter initialized");
        }
        
        // Initialize Shadowsocks adapter
        if config.shadowsocks.enabled {
            let adapter = ShadowsocksAdapter::new(config.shadowsocks.clone(), key_store.clone()).await?;
            adapters.insert(ProtocolId::Shadowsocks, Box::new(adapter));
            info!("Shadowsocks adapter initialized");
        }
        
        // Initialize Hysteria2 adapter
        if config.hysteria2.enabled {
            let adapter = HysteriaAdapter::new(config.hysteria2.clone(), key_store.clone()).await?;
            adapters.insert(ProtocolId::Hysteria2, Box::new(adapter));
            info!("Hysteria2 adapter initialized");
        }
        
        // OpenVPN would be initialized here if enabled
        
        Ok(Self {
            config,
            key_store,
            api_client,
            adapters,
            active_session: RwLock::new(None),
            stats: RwLock::new(VpnStats::default()),
        })
    }
    
    pub async fn connect_best(&self) -> Result<ConnectionResult, WardenError> {
        // Fetch latest configs from API
        let configs = self.api_client.fetch_subscription(&self.get_token().await?).await?;
        
        // Filter alive configs
        let alive_configs: Vec<_> = configs.into_iter().filter(|c| c.is_alive).collect();
        
        if alive_configs.is_empty() {
            return Err(WardenError::NoConfigsAvailable);
        }
        
        // Sort by preference and health score
        let mut sorted = alive_configs;
        sorted.sort_by(|a, b| {
            let a_score = a.health_score.unwrap_or(0.5);
            let b_score = b.health_score.unwrap_or(0.5);
            b_score.partial_cmp(&a_score).unwrap()
        });
        
        // Try each protocol in fallback order
        for protocol_id in &self.config.fallback_order {
            let pid = ProtocolId::from(protocol_id.as_str());
            
            if let Some(adapter) = self.adapters.get(&pid) {
                // Find configs matching this protocol
                let matching: Vec<_> = sorted.iter().filter(|c| c.protocol == protocol_id).collect();
                
                for config in matching {
                    match self.connect_with_adapter(adapter.as_ref(), config).await {
                        Ok(result) => {
                            info!("Connected via {} to {}", protocol_id, config.host);
                            return Ok(result);
                        }
                        Err(e) => {
                            warn!("Failed to connect via {} to {}: {}", protocol_id, config.host, e);
                            continue;
                        }
                    }
                }
            }
        }
        
        Err(WardenError::AllConnectionsFailed)
    }
    
    async fn connect_with_adapter(
        &self,
        adapter: &dyn ProtocolAdapter,
        config: &ServerConfig,
    ) -> Result<ConnectionResult, WardenError> {
        let peer_addr = format!("{}:{}", config.host, config.port).parse()?;
        
        // Perform handshake
        let handshake_result = adapter.handshake(&adapter.config(), peer_addr).await?;
        
        // Create transport
        let transport = adapter.create_transport(&adapter.config(), handshake_result.clone()).await?;
        
        // Store active session
        let session = ActiveSession {
            session_id: handshake_result.session_id,
            protocol: adapter.protocol_id(),
            config: config.clone(),
            transport,
            started_at: Utc::now(),
            bytes_sent: 0,
            bytes_received: 0,
        };
        
        *self.active_session.write().await = Some(session);
        
        // Update stats
        let mut stats = self.stats.write().await;
        stats.total_connections += 1;
        stats.successful_connections += 1;
        stats.current_protocol = Some(adapter.protocol_id());
        stats.current_server = Some(format!("{}:{}", config.host, config.port));
        
        Ok(ConnectionResult {
            session_id: handshake_result.session_id,
            protocol: adapter.protocol_id(),
            server: format!("{}:{}", config.host, config.port),
            connected_at: Utc::now(),
        })
    }
    
    pub async fn disconnect(&self) -> Result<(), WardenError> {
        let mut session_guard = self.active_session.write().await;
        if let Some(session) = session_guard.take() {
            // Gracefully shutdown transport
            let _ = session.transport.poll_shutdown(&mut std::task::Context::from_waker(
                &std::task::Waker::noop()
            )).await;
            
            info!("Disconnected from {}", session.config.host);
        }
        
        let mut stats = self.stats.write().await;
        stats.current_protocol = None;
        stats.current_server = None;
        
        Ok(())
    }
    
    pub async fn get_status(&self) -> ConnectionStatus {
        let session = self.active_session.read().await;
        let stats = self.stats.read().await;
        
        if let Some(session) = session.as_ref() {
            ConnectionStatus::Connected {
                session_id: session.session_id,
                protocol: session.protocol,
                server: format!("{}:{}", session.config.host, session.config.port),
                connected_at: session.started_at,
                bytes_sent: session.bytes_sent,
                bytes_received: session.bytes_received,
                uptime: (Utc::now() - session.started_at).num_seconds() as u64,
            }
        } else {
            ConnectionStatus::Disconnected {
                last_protocol: stats.current_protocol,
                last_server: stats.current_server,
                total_connections: stats.total_connections,
                successful_connections: stats.successful_connections,
            }
        }
    }
    
    pub async fn get_stats(&self) -> VpnStats {
        self.stats.read().await.clone()
    }
    
    pub async fn test_config(&self, config: &ServerConfig) -> Result<TestResult, WardenError> {
        let protocol_id = ProtocolId::from(config.protocol.as_str());
        
        if let Some(adapter) = self.adapters.get(&protocol_id) {
            let start = std::time::Instant::now();
            let peer_addr = format!("{}:{}", config.host, config.port).parse()?;
            
            match adapter.handshake(&adapter.config(), peer_addr).await {
                Ok(handshake_result) => {
                    let latency = start.elapsed().as_millis() as u64;
                    
                    // Quick connectivity test
                    let transport = adapter.create_transport(&adapter.config(), handshake_result).await?;
                    let test_passed = self.quick_test(transport).await;
                    
                    Ok(TestResult {
                        config_id: config.id,
                        protocol: protocol_id,
                        latency_ms: latency,
                        success: test_passed,
                        tested_at: Utc::now(),
                    })
                }
                Err(e) => Ok(TestResult {
                    config_id: config.id,
                    protocol: protocol_id,
                    latency_ms: 0,
                    success: false,
                    tested_at: Utc::now(),
                })
            }
        } else {
            Err(WardenError::ProtocolNotSupported(protocol_id.as_str().to_string()))
        }
    }
    
    async fn quick_test(&self, mut transport: Box<dyn ProtocolTransport>) -> bool {
        // Send a small test packet and wait for response
        let test_data = b"WARDEN_TEST";
        let mut buf = vec![0u8; 1024];
        
        if transport.poll_write(&mut std::task::Context::from_waker(&std::task::Waker::noop()), test_data).await.is_ok() {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            transport.poll_read(&mut std::task::Context::from_waker(&std::task::Waker::noop()), &mut buf).await.is_ok()
        } else {
            false
        }
    }
    
    async fn get_token(&self) -> Result<String, WardenError> {
        // Get token from config or secure storage
        self.config.api.auth_token.clone().ok_or(WardenError::AuthTokenMissing)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionResult {
    pub session_id: Uuid,
    pub protocol: ProtocolId,
    pub server: String,
    pub connected_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected {
        session_id: Uuid,
        protocol: ProtocolId,
        server: String,
        connected_at: chrono::DateTime<Utc>,
        bytes_sent: u64,
        bytes_received: u64,
        uptime: u64,
    },
    Disconnected {
        last_protocol: Option<ProtocolId>,
        last_server: Option<String>,
        total_connections: u64,
        successful_connections: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub config_id: i64,
    pub protocol: ProtocolId,
    pub latency_ms: u64,
    pub success: bool,
    pub tested_at: chrono::DateTime<Utc>,
}