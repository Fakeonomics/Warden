use crate::config::OpsecConfig;

pub struct OpsecManager {
    config: OpsecConfig,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct OpsecStatus {
    pub enabled: bool,
    pub fingerprint_rotation: bool,
    pub traffic_shaping: bool,
    pub hwid_spoof: bool,
    pub kill_switch: bool,
    pub dns_leak_protection: bool,
    pub padding: bool,
}

impl OpsecManager {
    pub fn new(config: OpsecConfig) -> Self {
        Self { config }
    }

    pub fn status(&self) -> OpsecStatus {
        OpsecStatus {
            enabled: self.config.enabled,
            fingerprint_rotation: self.config.fingerprint_rotation,
            traffic_shaping: self.config.traffic_shaping,
            hwid_spoof: self.config.hwid_spoof,
            kill_switch: self.config.kill_switch,
            dns_leak_protection: self.config.dns_leak_protection,
            padding: self.config.padding,
        }
    }

    /// Generate a spoofed HWID string — randomized per boot, stable within session.
    pub fn generate_hwid(&self) -> String {
        if !self.config.hwid_spoof {
            return String::new();
        }
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut buf = [0u8; 16];
        let _ = rng.fill(&mut buf);
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, buf)
    }

    /// Pick a fresh browser fingerprint from our pool.
    pub fn pick_fingerprint(&self) -> &str {
        const FPS: &[&str] = &["chrome", "firefox", "safari", "edge", "360", "qq"];
        if !self.config.fingerprint_rotation {
            return "chrome";
        }
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut idx = [0u8; 1];
        let _ = rng.fill(&mut idx);
        FPS[(idx[0] as usize) % FPS.len()]
    }
}
