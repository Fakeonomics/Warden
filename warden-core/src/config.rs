use litcrypt2::lc;
use serde::{Deserialize, Serialize};

lc!();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    Civilian,
    Operator,
}

impl Default for Mode {
    fn default() -> Self { Mode::Civilian }
}

impl Mode {
    pub fn is_operator(&self) -> bool { matches!(self, Mode::Operator) }
    pub fn unlock(code: &str) -> Self {
        let key = lc!("GREYHOUND-19-OPERATOR");
        if code == key { Mode::Operator } else { Mode::Civilian }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WardenConfig {
    #[serde(default)]
    pub mode: Mode,
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
            base_url: lc!("https://fakeonomics.online"),
            subscription_endpoint: lc!("/sub/{token}/all.txt"),
            health_endpoint: lc!("/api/protocols"),
            auth_token: None,
            timeout_seconds: 30,
            user_agent: lc!("Warden/0.1.0"),
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
                lc!("vless").into(),
                lc!("hysteria2").into(),
                lc!("shadowsocks").into(),
                lc!("wireguard").into(),
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
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 30,
            max_failures_before_rotate: 3,
            prefer_regions: vec![lc!("RU").into(), lc!("DE").into(), lc!("NL").into(), lc!("US").into(), lc!("FR").into()],
            exclude_countries: vec![lc!("CN").into(), lc!("KP").into(), lc!("IR").into()],
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
        Self { path: lc!("/root/vpn-service/data/vpn_service.db").into() }
    }
}

impl WardenConfig {
    pub fn load() -> anyhow::Result<Self> {
        if let Ok(p) = std::env::var("WARDEN_CONFIG") {
            let txt = std::fs::read_to_string(&p)?;
            let cfg: WardenConfig = serde_json::from_str(&txt)
                .or_else(|_| toml::from_str(&txt))
                .unwrap_or_default();
            return Ok(cfg);
        }
        Ok(Self::default())
    }
}
