use crate::config::{Mode, OpsecConfig};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::path::PathBuf;

const FINGERPRINTS: &[&str] = &["chrome", "firefox", "safari", "edge", "360", "qq"];
const HWID_FILE: &str = "hwid";
const FP_FILE: &str = "fp.idx";

pub struct OpsecManager {
    config: OpsecConfig,
    mode: Mode,
    hwid: Option<String>,
    hwid_file: Option<PathBuf>,
    fingerprint_index: u8,
    fp_file: Option<PathBuf>,
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
        Self {
            config,
            mode: Mode::default(),
            hwid: None,
            hwid_file: None,
            fingerprint_index: 0,
            fp_file: None,
        }
    }

    pub fn with_mode(config: OpsecConfig, mode: Mode) -> Self {
        Self::with_persistence(config, mode, None)
    }

    pub fn with_persistence(config: OpsecConfig, mode: Mode, data_dir: Option<PathBuf>) -> Self {
        let mut cfg = config;
        if mode.is_operator() {
            cfg.enabled = true;
        }

        let (hwid_file, fp_file) = match data_dir.as_ref() {
            Some(d) => {
                let _ = std::fs::create_dir_all(d);
                (Some(d.join(HWID_FILE)), Some(d.join(FP_FILE)))
            }
            None => (None, None),
        };

        let mut mgr = Self {
            config: cfg,
            mode,
            hwid: None,
            hwid_file,
            fingerprint_index: 0,
            fp_file,
        };

        if mgr.config.hwid_spoof {
            mgr.hwid = mgr.load_or_create_hwid();
        }
        mgr.fingerprint_index = mgr.load_fp_index();
        mgr
    }

    fn load_or_create_hwid(&mut self) -> Option<String> {
        let path = self.hwid_file.as_ref()?.clone();
        if let Ok(s) = std::fs::read_to_string(&path) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                let _ = std::fs::write(&path, s.as_bytes());
                return Some(s);
            }
        }
        let rng = SystemRandom::new();
        let mut buf = [0u8; 16];
        if rng.fill(&mut buf).is_err() {
            return None;
        }
        use base64::Engine;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        let _ = std::fs::write(&path, encoded.as_bytes());
        Some(encoded)
    }

    fn load_fp_index(&self) -> u8 {
        let path = match self.fp_file_path() {
            Some(p) => p,
            None => return 0,
        };
        if let Ok(s) = std::fs::read_to_string(&path) {
            let trimmed = s.trim();
            if let Ok(n) = trimmed.parse::<u8>() {
                return n % (FINGERPRINTS.len() as u8);
            }
        }
        0
    }

    fn fingerprint_file(&self) -> Option<PathBuf> {
        self.fp_file.clone()
    }
    fn fp_file_path(&self) -> Option<PathBuf> {
        self.fingerprint_file()
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn unlock(&mut self, code: &str) -> bool {
        let new_mode = Mode::unlock(code);
        if new_mode.is_operator() {
            self.mode = new_mode;
            self.config.enabled = true;
            if self.config.hwid_spoof && self.hwid.is_none() {
                self.hwid = self.load_or_create_hwid();
            }
            return true;
        }
        false
    }

    pub fn lock(&mut self) {
        self.mode = Mode::Civilian;
    }

    pub fn status(&mut self) -> OpsecStatus {
        if self.config.fingerprint_rotation {
            self.rotate_fingerprint();
        }
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
        if !self.mode.is_operator() {
            return false;
        }
        match field {
            "fingerprint_rotation" => self.config.fingerprint_rotation = val,
            "traffic_shaping" => self.config.traffic_shaping = val,
            "hwid_spoof" => {
                self.config.hwid_spoof = val;
                if val && self.hwid.is_none() {
                    self.hwid = self.load_or_create_hwid();
                }
            }
            "kill_switch" => self.config.kill_switch = val,
            "dns_leak_protection" => self.config.dns_leak_protection = val,
            "padding" => self.config.padding = val,
            _ => return false,
        }
        true
    }

    pub fn generate_hwid(&self) -> String {
        if !self.config.hwid_spoof {
            return String::new();
        }
        self.hwid.clone().unwrap_or_default()
    }

    pub fn pick_fingerprint(&self) -> &'static str {
        if !self.config.fingerprint_rotation {
            return "chrome";
        }
        let idx = (self.fingerprint_index as usize) % FINGERPRINTS.len();
        FINGERPRINTS[idx]
    }

    pub fn rotate_fingerprint(&mut self) {
        let len = FINGERPRINTS.len() as u8;
        let next = if self.fingerprint_index.wrapping_add(1) >= len {
            0
        } else {
            self.fingerprint_index.wrapping_add(1)
        };
        self.fingerprint_index = next;
        if let Some(p) = self.fp_file_path() {
            let _ = std::fs::write(&p, next.to_string().as_bytes());
        }
    }

    pub fn padding_size(&self) -> usize {
        if !self.config.padding {
            return 0;
        }
        let rng = SystemRandom::new();
        let mut buf = [0u8; 1];
        let _ = rng.fill(&mut buf);
        buf[0] as usize
    }

    pub fn on_kill_switch(&self) {
        if self.config.kill_switch {
            tracing::warn!("kill-switch engaged (log only; real firewall requires root)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(hwid_spoof: bool, fp_rot: bool) -> OpsecConfig {
        OpsecConfig {
            enabled: true,
            fingerprint_rotation: fp_rot,
            traffic_shaping: false,
            hwid_spoof,
            kill_switch: false,
            dns_leak_protection: false,
            padding: false,
            auto_on_connect: false,
        }
    }

    #[test]
    fn t_hwid_persists() {
        let dir = std::env::temp_dir().join(format!("warden-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let c = cfg(true, false);
        let a = OpsecManager::with_persistence(c.clone(), Mode::Civilian, Some(dir.clone()));
        let hwid_a = a.generate_hwid();
        assert!(!hwid_a.is_empty(), "hwid should be generated");

        let b = OpsecManager::with_persistence(c, Mode::Civilian, Some(dir.clone()));
        let hwid_b = b.generate_hwid();
        assert_eq!(
            hwid_a, hwid_b,
            "persisted hwid should match across managers"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t_hwid_empty_when_off() {
        let c = cfg(false, false);
        let m = OpsecManager::with_persistence(c, Mode::Civilian, Some(std::env::temp_dir()));
        assert_eq!(m.generate_hwid(), "");
    }

    #[test]
    fn t_fingerprint_rotation() {
        let c = cfg(false, true);
        let dir = std::env::temp_dir().join(format!("warden-test-fp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut m = OpsecManager::with_persistence(c, Mode::Civilian, Some(dir.clone()));

        let mut seen = Vec::new();
        let len = FINGERPRINTS.len();
        for _ in 0..len {
            seen.push(m.pick_fingerprint().to_string());
            m.rotate_fingerprint();
        }
        let unique: std::collections::HashSet<_> = seen.iter().collect();
        assert_eq!(unique.len(), len, "should walk through all fps: {seen:?}");

        let before = m.fingerprint_index;
        m.rotate_fingerprint();
        let after = m.fingerprint_index;
        let wrapped = (after == 0 && before == (len as u8) - 1) || after == before + 1;
        assert!(
            wrapped,
            "rotation should advance, possibly wrapping (before={before} after={after})"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn t_fingerprint_rotation_deterministic() {
        // Rotation must be deterministic: same starting index, same sequence.
        let dir_a = std::env::temp_dir().join(format!("warden-test-fp-a-{}", std::process::id()));
        let dir_b = std::env::temp_dir().join(format!("warden-test-fp-b-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);

        let c = cfg(false, true);
        let mut a = OpsecManager::with_persistence(c.clone(), Mode::Civilian, Some(dir_a.clone()));
        let mut b = OpsecManager::with_persistence(c, Mode::Civilian, Some(dir_b.clone()));

        for _ in 0..(FINGERPRINTS.len() + 2) {
            assert_eq!(
                a.pick_fingerprint(),
                b.pick_fingerprint(),
                "rotation must be deterministic"
            );
            a.rotate_fingerprint();
            b.rotate_fingerprint();
        }

        // Reload from disk: persisted index must survive restart.
        let reloaded =
            OpsecManager::with_persistence(cfg(false, true), Mode::Civilian, Some(dir_a.clone()));
        assert_eq!(
            reloaded.fingerprint_index, a.fingerprint_index,
            "fp index must persist across restart"
        );

        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn t_status_does_not_panic_when_off() {
        let c = cfg(false, false);
        let mut m = OpsecManager::new(c);
        let st = m.status();
        assert!(!st.mode_operator);
        assert_eq!(st.current_fingerprint, "chrome");
        assert_eq!(st.current_hwid, "");
    }
}
