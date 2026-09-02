use crate::error::WardenError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Mode {
    #[default]
    Civilian,
    Operator,
}

impl Mode {
    pub fn is_operator(&self) -> bool {
        matches!(self, Mode::Operator)
    }
    pub fn unlock(code: &str) -> Self {
        #[cfg(debug_assertions)]
        let key = "GREYHOUND-19-OPERATOR";
        #[cfg(not(debug_assertions))]
        let key = "";
        if code == key {
            Mode::Operator
        } else {
            Mode::Civilian
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum PerformanceMode {
    Speed,
    Stealth,
    #[default]
    Balanced,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub performance_mode: PerformanceMode,
    pub api: ApiConfig,
    pub protocols: ProtocolsConfig,
    pub rotation: RotationConfig,
    pub opsec: OpsecConfig,
    pub database: DatabaseConfig,
}

impl Default for WardenConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Civilian,
            performance_mode: PerformanceMode::Balanced,
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
            preferred: vec![
                "vless".into(),
                "hysteria2".into(),
                "shadowsocks".into(),
                "wireguard".into(),
            ],
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
    pub exclude_countries: Vec<String>,
    /// Optional explicit override for the parallel-connection count.
    /// When `None`, the hardware auto-tuner derives it from the CPU core
    /// count at startup. Backward-compatible: absent in old configs.
    #[serde(default)]
    pub parallel_connections: Option<usize>,
    /// Optional explicit override for the handshake timeout (seconds).
    /// When `None`, the auto-tuner derives it from available bandwidth.
    #[serde(default)]
    pub handshake_timeout_secs: Option<u64>,
    /// Optional explicit override for the worker-thread count used by the
    /// parallel probe. When `None`, the auto-tuner derives it.
    #[serde(default)]
    pub worker_threads: Option<usize>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 30,
            max_failures_before_rotate: 3,
            prefer_regions: vec![
                "RU".into(),
                "DE".into(),
                "NL".into(),
                "US".into(),
                "FR".into(),
            ],
            exclude_countries: vec!["CN".into(), "KP".into(), "IR".into()],
            parallel_connections: None,
            handshake_timeout_secs: None,
            worker_threads: None,
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
    #[serde(default)]
    pub auto_on_connect: bool,
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
            auto_on_connect: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: std::path::PathBuf,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        let mut path = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
        path.push(".local");
        path.push("share");
        path.push("warden");
        path.push("vpn_service.db");
        Self { path }
    }
}

impl WardenConfig {
    pub fn load() -> Result<Self, WardenError> {
        if let Ok(p) = std::env::var("WARDEN_CONFIG") {
            let txt = std::fs::read_to_string(&p)?;
            let cfg: WardenConfig = serde_json::from_str(&txt)
                .or_else(|_| toml::from_str(&txt))
                .map_err(|e| WardenError::ConfigParseError(e.to_string()))?;
            return Ok(cfg);
        }
        Ok(Self::default())
    }
}
