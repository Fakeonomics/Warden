use warden_core::{config::*, models::*, error::*};
use warden_api::ApiClient;
use warden_proto::{ProtocolId, ProtocolCapabilities, HandshakeResult, SessionKeys, ProtocolTransport, ProtocolAdapter};
use warden_wireguard::WireGuardAdapter;
use warden_vless::VlessAdapter;
use warden_shadowsocks::ShadowsocksAdapter;
use warden_hysteria::HysteriaAdapter;
use warden_session::SessionManager;
use warden_policy::PolicyEngine;
use warden_transport::TransportManager;
use warden_crypto::{KeyStore, SoftwareKeyStore, KeyPurpose};
use warden_metrics::MetricsCollector;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

pub struct AppState {
    pub config: Arc<WardenConfig>,
    pub vpn_manager: Arc<VpnManager>,
    pub opsec_manager: Arc<OpsecManager>,
    pub rotation_manager: Arc<RotationManager>,
    pub config_manager: Arc<ConfigManager>,
    pub api_client: Arc<ApiClient>,
    pub key_store: Arc<dyn KeyStore>,
    pub metrics: Arc<MetricsCollector>,
}