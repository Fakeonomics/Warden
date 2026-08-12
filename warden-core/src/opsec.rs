use crate::config::{Mode, OpsecConfig};
use litcrypt2::lc;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

lc!();

pub struct OpsecManager {
    config: OpsecConfig,
    mode: Mode,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpsecStatus {
    pub enabled: bool,
    pub mode_operator: bool,
    pub fingerprint_rotation: bool,
    pub traffic_shaping: bool,
    pub hwid_spoof: bool,
    pub kill_switch: bool,
    pub dns_leak_protection: bool,
    pub padding: bool,
    pub current_fingerprint: String,
    pub current_hwid: String,
}

impl OpsecManager {
    pub fn new(config: OpsecConfig) -> Self {
        Self { config, mode: Mode::default() }
    }

    pub fn with_mode(config: OpsecConfig, mode: Mode) -> Self {
        // operator mode обеспсивает full opsec regardless of toggles.
        let mut cfg = config;
        if mode.is_operator() { cfg.enabled = true; }
        Self { config: cfg, mode }
    }

    pub fn mode(&self) -> Mode { self.mode }

    pub fn unlock(&mut self, code: &str) -> bool {
        let new_mode = Mode::unlock(code);
        if new_mode.is_operator() {
            self.mode = new_mode;
            self.config.enabled = true;
            return true;
        }
        false
    }

    pub fn lock(&mut self) { self.mode = Mode::Civilian; }

    pub fn status(&self) -> OpsecStatus {
        OpsecStatus {
            enabled: self.config.enabled,
            mode_operator: self.mode.is_operator(),
            fingerprint_rotation: self.config.fingerprint_rotation,
            traffic_shaping: self.config.traffic_shaping,
            hwid_spoof: self.config.hwid_spoof,
            kill_switch: self.config.kill_switch,
            dns_leak_protection: self.config.dns_leak_protection,
            padding: self.config.padding,
            current_fingerprint: self.pick_fingerprint().into(),
            current_hwid: self.generate_hwid(),
        }
    }

    pub fn toggle(&mut self, field: &str, val: bool) -> bool {
        if !self.mode.is_operator() { return false; }
        match field {
            f if f == "fingerprint_rotation" => self.config.fingerprint_rotation = val,
            f if f == "traffic_shaping" => self.config.traffic_shaping = val,
            f if f == "hwid_spoof" => self.config.hwid_spoof = val,
            f if f == "kill_switch" => self.config.kill_switch = val,
            f if f == "dns_leak_protection" => self.config.dns_leak_protection = val,
            f if f == "padding" => self.config.padding = val,
            _ => return false,
        }
        true
    }

    pub fn generate_hwid(&self) -> String {
        if !self.config.hwid_spoof { return String::new(); }
        let rng = SystemRandom::new();
        let mut buf = [0u8; 16];
        let _ = rng.fill(&mut buf);
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    pub fn pick_fingerprint(&self) -> &'static str {
        const FPS: &[&str] = &["chrome", "firefox", "safari", "edge", "360", "qq"];
        if !self.config.fingerprint_rotation { return "chrome"; }
        let rng = SystemRandom::new();
        let mut idx = [0u8; 1];
        let _ = rng.fill(&mut idx);
        let masked = idx[0].wrapping_mul(0x9Eu8);
        FPS[(masked as usize) % FPS.len()]
    }

    /// Padding bytes for frame obfuscation, range [0,256].
    pub fn padding_size(&self) -> usize {
        if !self.config.padding { return 0; }
        let rng = SystemRandom::new();
        let mut buf = [0u8; 1];
        let _ = rng.fill(&mut buf);
        buf[0] as usize
    }

    /// Kill-switch callback — invoked when session is lost.
    pub fn on_kill_switch(&self) {
        if self.config.kill_switch {
            tracing::warn!("kill-switch engaged");
        }
    }
}
