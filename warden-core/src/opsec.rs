use crate::config::{Mode, OpsecConfig};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

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
            "fingerprint_rotation" => self.config.fingerprint_rotation = val,
            "traffic_shaping" => self.config.traffic_shaping = val,
            "hwid_spoof" => self.config.hwid_spoof = val,
            "kill_switch" => self.config.kill_switch = val,
            "dns_leak_protection" => self.config.dns_leak_protection = val,
            "padding" => self.config.padding = val,
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

#[cfg(test)]
mod tests {
    use super::*;
    use litcrypt2::lc;

    #[test]
    fn new_defaults_to_civilian() {
        let opsec = OpsecManager::new(OpsecConfig::default());
        assert_eq!(opsec.mode(), Mode::Civilian);
        assert!(!opsec.mode().is_operator());
    }

    #[test]
    fn with_mode_operator_sets_enabled() {
        let mut cfg = OpsecConfig::default();
        cfg.enabled = false;
        let opsec = OpsecManager::with_mode(cfg, Mode::Operator);
        assert!(opsec.mode().is_operator());
        let status = opsec.status();
        assert!(status.enabled);
        assert!(status.mode_operator);
    }

    #[test]
    fn with_mode_civilian_keeps_config() {
        let mut cfg = OpsecConfig::default();
        cfg.enabled = false;
        let opsec = OpsecManager::with_mode(cfg, Mode::Civilian);
        let status = opsec.status();
        assert!(!status.enabled);
        assert!(!status.mode_operator);
    }

    #[test]
    fn unlock_correct_code() {
        let mut opsec = OpsecManager::new(OpsecConfig::default());
        let key = lc!("GREYHOUND-19-OPERATOR");
        assert!(opsec.unlock(&key));
        assert!(opsec.mode().is_operator());
    }

    #[test]
    fn unlock_wrong_code() {
        let mut opsec = OpsecManager::new(OpsecConfig::default());
        assert!(!opsec.unlock("wrong"));
        assert!(!opsec.mode().is_operator());
    }

    #[test]
    fn unlock_empty_code() {
        let mut opsec = OpsecManager::new(OpsecConfig::default());
        assert!(!opsec.unlock(""));
        assert!(!opsec.mode().is_operator());
    }

    #[test]
    fn lock_resets_to_civilian() {
        let mut opsec = OpsecManager::new(OpsecConfig::default());
        let key = lc!("GREYHOUND-19-OPERATOR");
        opsec.unlock(&key);
        assert!(opsec.mode().is_operator());
        opsec.lock();
        assert!(!opsec.mode().is_operator());
    }

    #[test]
    fn generate_hwid_non_empty_when_enabled() {
        let opsec = OpsecManager::new(OpsecConfig::default());
        let hwid = opsec.generate_hwid();
        assert!(!hwid.is_empty());
        // base64 of 16 bytes with URL_SAFE_NO_PAD should be ~22 chars
        assert!(hwid.len() >= 20);
    }

    #[test]
    fn generate_hwid_empty_when_disabled() {
        let mut cfg = OpsecConfig::default();
        cfg.hwid_spoof = false;
        let opsec = OpsecManager::new(cfg);
        assert!(opsec.generate_hwid().is_empty());
    }

    #[test]
    fn generate_hwid_different_each_call() {
        let opsec = OpsecManager::new(OpsecConfig::default());
        let hwid1 = opsec.generate_hwid();
        let hwid2 = opsec.generate_hwid();
        assert_ne!(hwid1, hwid2);
    }

    #[test]
    fn pick_fingerprint_returns_valid() {
        let opsec = OpsecManager::new(OpsecConfig::default());
        let fp = opsec.pick_fingerprint();
        let valid = ["chrome", "firefox", "safari", "edge", "360", "qq"];
        assert!(valid.contains(&fp), "fingerprint '{}' is not in the valid set", fp);
    }

    #[test]
    fn pick_fingerprint_fixed_when_rotation_disabled() {
        let mut cfg = OpsecConfig::default();
        cfg.fingerprint_rotation = false;
        let opsec = OpsecManager::new(cfg);
        assert_eq!(opsec.pick_fingerprint(), "chrome");
    }

    #[test]
    fn padding_size_zero_when_disabled() {
        let mut cfg = OpsecConfig::default();
        cfg.padding = false;
        let opsec = OpsecManager::new(cfg);
        assert_eq!(opsec.padding_size(), 0);
    }

    #[test]
    fn padding_size_in_range_when_enabled() {
        let opsec = OpsecManager::new(OpsecConfig::default());
        for _ in 0..100 {
            let p = opsec.padding_size();
            assert!(p <= 255, "padding_size {} exceeds range [0,255]", p);
        }
    }

    #[test]
    fn toggle_requires_operator_mode() {
        let mut opsec = OpsecManager::new(OpsecConfig::default());
        assert!(!opsec.toggle("kill_switch", false));
    }

    #[test]
    fn toggle_valid_field_operator() {
        let mut opsec = OpsecManager::with_mode(OpsecConfig::default(), Mode::Operator);
        assert!(opsec.toggle("kill_switch", false));
        assert!(!opsec.status().kill_switch);
        assert!(opsec.toggle("kill_switch", true));
        assert!(opsec.status().kill_switch);
    }

    #[test]
    fn toggle_invalid_field() {
        let mut opsec = OpsecManager::with_mode(OpsecConfig::default(), Mode::Operator);
        assert!(!opsec.toggle("nonexistent_field", true));
    }

    #[test]
    fn toggle_all_features() {
        let mut opsec = OpsecManager::with_mode(OpsecConfig::default(), Mode::Operator);
        assert!(opsec.toggle("fingerprint_rotation", false));
        assert!(opsec.toggle("traffic_shaping", false));
        assert!(opsec.toggle("hwid_spoof", false));
        assert!(opsec.toggle("kill_switch", false));
        assert!(opsec.toggle("dns_leak_protection", false));
        assert!(opsec.toggle("padding", false));
        let s = opsec.status();
        assert!(!s.fingerprint_rotation);
        assert!(!s.traffic_shaping);
        assert!(!s.hwid_spoof);
        assert!(!s.kill_switch);
        assert!(!s.dns_leak_protection);
        assert!(!s.padding);
    }

    #[test]
    fn status_reflects_config() {
        let mut cfg = OpsecConfig::default();
        cfg.enabled = true;
        cfg.fingerprint_rotation = false;
        cfg.hwid_spoof = false;
        let opsec = OpsecManager::new(cfg);
        let s = opsec.status();
        assert!(s.enabled);
        assert!(!s.fingerprint_rotation);
        assert!(!s.hwid_spoof);
        assert!(!s.mode_operator);
    }

    #[test]
    fn on_kill_switch_no_panic_when_disabled() {
        let mut cfg = OpsecConfig::default();
        cfg.kill_switch = false;
        let opsec = OpsecManager::new(cfg);
        opsec.on_kill_switch();
    }

    #[test]
    fn on_kill_switch_no_panic_when_enabled() {
        let opsec = OpsecManager::new(OpsecConfig::default());
        opsec.on_kill_switch();
    }
}
