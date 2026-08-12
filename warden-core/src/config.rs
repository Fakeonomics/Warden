use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    pub api: ApiConfig,
    pub protocols: ProtocolsConfig,
    pub rotation: RotationConfig,
    pub opsec: OpsecConfig,
    pub database: DatabaseConfig,
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            api: ApiConfig::default(),
            protocols: ProtocolsConfig::default(),
            rotation: RotationConfig::default(),
            opsec: OpsecConfig::default(),
            database: DatabaseConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub base_url: String,
    pub subscription_endpoint: String,
    pub health_endpoint: String,
    pub auth_token: Option<String>,
    pub timeout_seconds: u64,
    pub user_agent: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            base_url: "https://fakeonomics.online".into(),
            subscription_endpoint: "/sub/{token}/all.txt".into(),
            health_endpoint: "/api/protocols".into(),
            auth_token: None,
            timeout_seconds: 30,
            user_agent: "Warden/0.1.0".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolsConfig {
    pub preferred: Vec<String>,
    pub wireguard_enabled: bool,
    pub vless_enabled: bool,
    pub shadowsocks_enabled: bool,
    pub hysteria2_enabled: bool,
}

impl Default for ProtocolsConfig {
    fn default() -> Self {
        Self {
            preferred: vec!["vless".into(), "hysteria2".into(), "shadowsocks".into(), "wireguard".into()],
            wireguard_enabled: true,
            vless_enabled: true,
            shadowsocks_enabled: true,
            hysteria2_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub max_failures_before_rotate: u32,
    pub prefer_regions: Vec<String>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 30,
            max_failures_before_rotate: 3,
            prefer_regions: vec!["RU".into(), "DE".into(), "NL".into(), "US".into(), "FR".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsecConfig {
    pub enabled: bool,
    pub fingerprint_rotation: bool,
    pub traffic_shaping: bool,
    pub hwid_spoof: bool,
    pub kill_switch: bool,
    pub dns_leak_protection: bool,
    pub padding: bool,
}

impl Default for OpsecConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fingerprint_rotation: true,
            traffic_shaping: true,
            hwid_spoof: true,
            kill_switch: true,
            dns_leak_protection: true,
            padding: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self { path: PathBuf::from("/root/vpn-service/data/vpn_service.db") }
    }
}

impl WardenConfig {
    pub fn load() -> anyhow::Result<Self> {
        if let Ok(s) = std::env::var("WARDEN_CONFIG") {
            let txt = std::fs::read_to_string(&s)?;
            let cfg: WardenConfig = serde_json::from_str(&txt)
                .or_else(|_| toml::from_str(&txt))
                .unwrap_or_default();
            return Ok(cfg);
        }
        Ok(Self::default())
    }
}
