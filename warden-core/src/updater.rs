use crate::error::WardenError;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::path::PathBuf;

pub static LOCAL_VERSION: &str = "0.1.0";

pub fn local_version() -> &'static str {
    LOCAL_VERSION
}

pub fn current_target() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Result<Self, WardenError> {
        let mut s = s.trim().to_string();
        while let Some(stripped) = s.strip_prefix('v').or_else(|| s.strip_prefix('V')) {
            s = stripped.to_string();
        }
        let mut parts = s.splitn(2, '-');
        let numeric = parts.next().unwrap_or("");
        let pre = parts.next().map(|t| t.to_string());
        let nums: Vec<&str> = numeric.split('.').collect();
        if nums.len() < 3 {
            return Err(WardenError::Update(format!("invalid version: {s}")));
        }
        let parse_u64 = |t: &str| -> Result<u64, WardenError> {
            t.parse::<u64>()
                .map_err(|_| WardenError::Update(format!("invalid version number: {t}")))
        };
        let major = parse_u64(nums[0])?;
        let minor = parse_u64(nums[1])?;
        let patch = parse_u64(nums[2])?;
        let pre = match pre {
            Some(p) if p.is_empty() => None,
            other => other,
        };
        Ok(Version {
            major,
            minor,
            patch,
            pre,
        })
    }

    pub fn cmp_pre(a: &Option<String>, b: &Option<String>) -> Ordering {
        match (a, b) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(x), Some(y)) => x.cmp(y),
        }
    }

    pub fn compare(&self, other: &Version) -> Ordering {
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| Self::cmp_pre(&self.pre, &other.pre))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare(other)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    #[serde(rename = "browser_download_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub tag_name: String,
    pub name: String,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}

impl ReleaseInfo {
    pub fn version(&self) -> Result<Version, WardenError> {
        Version::parse(&self.tag_name)
    }

    pub fn asset_for(&self, target: &str) -> Option<&Asset> {
        if let Some(a) = self.assets.iter().find(|a| a.name.contains(target)) {
            return Some(a);
        }
        let want = format!("warden-{target}");
        self.assets.iter().find(|a| a.name == want)
    }
}

#[derive(Debug, Clone)]
pub struct Updater {
    pub client: reqwest::Client,
    pub user_agent: String,
    pub repo: String,
}

impl Updater {
    pub fn with_default_client(user_agent: String, repo: String) -> Result<Self, WardenError> {
        let client = reqwest::Client::builder()
            .user_agent(user_agent.clone())
            .build()?;
        Ok(Self {
            client,
            user_agent,
            repo,
        })
    }

    pub fn new(client: reqwest::Client, user_agent: String, repo: String) -> Self {
        Self {
            client,
            user_agent,
            repo,
        }
    }

    pub fn local() -> &'static str {
        LOCAL_VERSION
    }

    pub async fn check(&self) -> Result<Option<ReleaseInfo>, WardenError> {
        let url = format!("https://api.github.com/repos/{}/releases/latest", self.repo);
        let resp = self
            .client
            .get(&url)
            .header(reqwest::header::USER_AGENT, self.user_agent.clone())
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .send()
            .await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(WardenError::Download(format!("github http {status}")));
        }
        let info: ReleaseInfo = resp.json().await?;
        Ok(Some(info))
    }

    pub async fn download_asset(&self, asset: &Asset) -> Result<Vec<u8>, WardenError> {
        let resp = self
            .client
            .get(&asset.url)
            .header(reqwest::header::USER_AGENT, self.user_agent.clone())
            .header(reqwest::header::ACCEPT, "application/octet-stream")
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(WardenError::Download(format!(
                "asset http {}",
                resp.status()
            )));
        }
        let bytes = resp.bytes().await?;
        Ok(bytes.to_vec())
    }

    pub async fn install(&self, bytes: &[u8]) -> Result<(), WardenError> {
        let exe = std::env::current_exe()?;
        let parent = exe
            .parent()
            .ok_or_else(|| WardenError::Download("no parent dir".into()))?;
        let pid = std::process::id();
        let tmp: PathBuf = parent.join(format!("warden.new.{pid}"));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &exe)?;
        Ok(())
    }

    /// Install + spawn a detached relauncher that replaces the running
    /// process. Returns the path of the new binary; the current process
    /// is expected to exit afterwards.
    pub async fn install_and_relaunch(&self, bytes: &[u8]) -> Result<PathBuf, WardenError> {
        let exe = std::env::current_exe()?;
        self.install(bytes).await?;
        // Re-exec in a child that replaces the current process. On Linux
        // we use execve via a shell that runs the just-installed binary.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let _ = std::process::Command::new(&exe)
                .arg("self-test")
                .exec();
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Best-effort: just spawn the new version in background.
            let _ = std::process::Command::new(&exe).spawn();
        }
        Ok(exe)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateCheck {
    pub local: String,
    pub remote: Option<String>,
    pub available: bool,
}

impl UpdateCheck {
    pub fn from(local: &str, remote: Option<&Version>) -> Self {
        let remote_str = remote.map(|v| format!("{}.{}.{}", v.major, v.minor, v.patch));
        let available = match remote {
            Some(r) => match Version::parse(local) {
                Ok(l) => l.compare(r).is_lt(),
                Err(_) => false,
            },
            None => false,
        };
        Self {
            local: local.into(),
            remote: remote_str,
            available,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_version_parse_simple() {
        let v = Version::parse("0.1.0").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (0, 1, 0));
        assert!(v.pre.is_none());

        let v = Version::parse("v1.2.3-beta").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (1, 2, 3));
        assert_eq!(v.pre.as_deref(), Some("beta"));

        let v = Version::parse("V2.0.0").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (2, 0, 0));
        assert!(v.pre.is_none());
    }

    #[test]
    fn t_version_cmp() {
        let a = Version::parse("0.1.0").unwrap();
        let b = Version::parse("0.1.1").unwrap();
        assert_eq!(a.compare(&b), Ordering::Less);

        let a = Version::parse("0.2.0").unwrap();
        let b = Version::parse("0.1.9").unwrap();
        assert_eq!(a.compare(&b), Ordering::Greater);

        let a = Version::parse("1.0.0").unwrap();
        let b = Version::parse("1.0.0").unwrap();
        assert_eq!(a.compare(&b), Ordering::Equal);

        let a = Version::parse("1.0.0").unwrap();
        let b = Version::parse("1.0.0-beta").unwrap();
        assert_eq!(a.compare(&b), Ordering::Greater);
    }

    #[test]
    fn t_release_parse_and_asset_for() {
        let json = r#"{"tag_name":"v0.2.0","name":"v0.2.0","prerelease":false,"assets":[{"name":"warden-x86_64-linux","browser_download_url":"https://example/x"}]}"#;
        let info: ReleaseInfo = serde_json::from_str(json).unwrap();
        let v = info.version().unwrap();
        assert_eq!((v.major, v.minor, v.patch), (0, 2, 0));
        let a = info.asset_for("x86_64-linux").unwrap();
        assert_eq!(a.url, "https://example/x");
        assert_eq!(a.name, "warden-x86_64-linux");
    }

    #[test]
    fn t_asset_for_none() {
        let json = r#"{"tag_name":"v0.2.0","name":"v0.2.0","prerelease":false,"assets":[{"name":"warden-aarch64-linux","browser_download_url":"https://example/x"}]}"#;
        let info: ReleaseInfo = serde_json::from_str(json).unwrap();
        assert!(info.asset_for("x86_64-linux").is_none());
    }

    #[test]
    fn t_current_target() {
        let t = current_target();
        assert!(t.contains('-'));
        assert!(t.contains(std::env::consts::ARCH));
    }
}
