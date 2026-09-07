use litcrypt2::lc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Mode {
    #[default]
    Civilian,
    Operator,
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
                lc!("vless"),
                lc!("hysteria2"),
                lc!("shadowsocks"),
                lc!("wireguard"),
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
            prefer_regions: vec![lc!("RU"), lc!("DE"), lc!("NL"), lc!("US"), lc!("FR")],
            exclude_countries: vec![lc!("CN"), lc!("KP"), lc!("IR")],
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_default_is_civilian() {
        assert_eq!(Mode::default(), Mode::Civilian);
        assert!(!Mode::default().is_operator());
    }

    #[test]
    fn mode_is_operator() {
        assert!(Mode::Operator.is_operator());
        assert!(!Mode::Civilian.is_operator());
    }

    #[test]
    fn mode_unlock_with_correct_code() {
        let key = lc!("GREYHOUND-19-OPERATOR");
        assert_eq!(Mode::unlock(&key), Mode::Operator);
    }

    #[test]
    fn mode_unlock_with_wrong_code() {
        assert_eq!(Mode::unlock("wrong-code"), Mode::Civilian);
    }

    #[test]
    fn mode_unlock_with_empty_code() {
        assert_eq!(Mode::unlock(""), Mode::Civilian);
    }

    #[test]
    fn default_api_config() {
        let cfg = ApiConfig::default();
        let expected_base = lc!("https://fakeonomics.online");
        assert_eq!(cfg.base_url, expected_base);
        assert_eq!(cfg.timeout_seconds, 30);
        assert!(cfg.auth_token.is_none());

        let expected_ua = lc!("Warden/0.1.0");
        assert_eq!(cfg.user_agent, expected_ua);
    }

    #[test]
    fn default_protocols_config() {
        let cfg = ProtocolsConfig::default();
        assert!(cfg.wireguard_enabled);
        assert!(cfg.vless_enabled);
        assert!(cfg.shadowsocks_enabled);
        assert!(cfg.hysteria2_enabled);
        // vless should be first (highest preferred)
        assert_eq!(cfg.preferred[0], lc!("vless"));
        assert_eq!(cfg.preferred.len(), 4);
    }

    #[test]
    fn default_rotation_config() {
        let cfg = RotationConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.interval_seconds, 30);
        assert_eq!(cfg.max_failures_before_rotate, 3);
        assert_eq!(cfg.prefer_regions.len(), 5);
        assert_eq!(cfg.exclude_countries.len(), 3);
    }

    #[test]
    fn default_opsec_config() {
        let cfg = OpsecConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.fingerprint_rotation);
        assert!(cfg.traffic_shaping);
        assert!(cfg.hwid_spoof);
        assert!(cfg.kill_switch);
        assert!(cfg.dns_leak_protection);
        assert!(cfg.padding);
        assert!(!cfg.auto_on_connect);
    }

    #[test]
    fn default_warden_config() {
        let cfg = WardenConfig::default();
        assert_eq!(cfg.mode, Mode::Civilian);
        assert_eq!(cfg.protocols.preferred.len(), 4);
        assert!(cfg.rotation.enabled);
        assert!(cfg.opsec.enabled);
    }

    #[test]
    fn config_roundtrip_json() {
        let cfg = WardenConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: WardenConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mode, cfg.mode);
        assert_eq!(parsed.api.base_url, cfg.api.base_url);
        assert_eq!(parsed.protocols.preferred, cfg.protocols.preferred);
        assert_eq!(parsed.rotation.interval_seconds, cfg.rotation.interval_seconds);
    }

    #[test]
    fn load_from_file_json() {
        let tmp = tempfile_cfg_json();
        std::env::set_var("WARDEN_CONFIG", &tmp);
        let cfg = WardenConfig::load().unwrap();
        assert!(cfg.opsec.kill_switch);
        assert_eq!(cfg.api.base_url, lc!("https://example.test"));
        std::env::remove_var("WARDEN_CONFIG");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_from_file_toml() {
        let tmp = std::env::temp_dir().join("warden_test_toml.toml");
        let content = r#"
[api]
base_url = "https://toml.test"
subscription_endpoint = "/sub/{token}/all.txt"
health_endpoint = "/api/protocols"
timeout_seconds = 15
user_agent = "Warden/0.1.0"

[protocols]
preferred = ["vless", "wireguard"]
wireguard_enabled = true
vless_enabled = true
shadowsocks_enabled = false
hysteria2_enabled = false

[rotation]
enabled = true
interval_seconds = 60
max_failures_before_rotate = 5
prefer_regions = ["DE", "US"]
exclude_countries = ["CN"]

[opsec]
enabled = true
fingerprint_rotation = false
traffic_shaping = false
hwid_spoof = false
kill_switch = false
dns_leak_protection = false
padding = false

[database]
path = "/tmp/test.db"
"#;
        std::fs::write(&tmp, content).unwrap();
        std::env::set_var("WARDEN_CONFIG", &tmp);
        let cfg = WardenConfig::load().unwrap();
        assert_eq!(cfg.api.base_url, "https://toml.test");
        assert_eq!(cfg.api.timeout_seconds, 15);
        assert!(!cfg.opsec.kill_switch);
        assert_eq!(cfg.rotation.interval_seconds, 60);
        assert_eq!(cfg.protocols.preferred, vec!["vless", "wireguard"]);
        std::env::remove_var("WARDEN_CONFIG");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn load_default_when_no_config() {
        std::env::remove_var("WARDEN_CONFIG");
        let cfg = WardenConfig::load().unwrap();
        assert_eq!(cfg.mode, Mode::Civilian);
        assert_eq!(cfg.api.base_url, lc!("https://fakeonomics.online"));
    }

    fn tempfile_cfg_json() -> String {
        let tmp = std::env::temp_dir().join("warden_test_cfg.json");
        let content = r#"{
    "api": {
        "base_url": "https://example.test",
        "subscription_endpoint": "/sub/{token}/all.txt",
        "health_endpoint": "/api/protocols",
        "auth_token": null,
        "timeout_seconds": 30,
        "user_agent": "Warden/0.1.0"
    },
    "protocols": {
        "preferred": ["vless", "wireguard"],
        "wireguard_enabled": true,
        "vless_enabled": true,
        "shadowsocks_enabled": true,
        "hysteria2_enabled": true
    },
    "rotation": {
        "enabled": true,
        "interval_seconds": 30,
        "max_failures_before_rotate": 3,
        "prefer_regions": ["RU", "DE"],
        "exclude_countries": ["CN", "KP"]
    },
    "opsec": {
        "enabled": true,
        "fingerprint_rotation": true,
        "traffic_shaping": true,
        "hwid_spoof": true,
        "kill_switch": true,
        "dns_leak_protection": true,
        "padding": true,
        "auto_on_connect": true
    },
    "database": {
        "path": "/tmp/test.db"
    }
}"#;
        std::fs::write(&tmp, content).unwrap();
        tmp.to_string_lossy().to_string()
    }
}
