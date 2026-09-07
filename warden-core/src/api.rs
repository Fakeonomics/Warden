use crate::{config::ApiConfig, error::WardenError};
use litcrypt2::lc;
use reqwest::{Client, ClientBuilder, header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, error};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub id: i64,
    pub config_line: String,
    pub protocol: String,
    pub host: String,
    pub port: i32,
    pub is_alive: bool,
    pub source: Option<String>,
    pub health_score: Option<f64>,
    pub response_time_ms: Option<i32>,
    #[serde(default)]
    pub region: Option<String>,
}

pub struct ApiClient {
    http: Client,
    config: Arc<ApiConfig>,
    cache: RwLock<Option<CachedSub>>,
    limiter: Semaphore,
    last_req: RwLock<Instant>,
}

#[derive(Debug, Clone)]
struct CachedSub {
    token: String,
    configs: Vec<ServerConfig>,
    #[allow(dead_code)]
    fetched_at: chrono::DateTime<chrono::Utc>,
}

impl ApiClient {
    pub fn new(mut config: ApiConfig) -> Result<Self, WardenError> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&config.user_agent)?);
        if let Some(t) = &config.auth_token {
            headers.insert(lc!("Authorization").parse::<HeaderName>()?, HeaderValue::from_str(&format!("Bearer {}", t))?);
        }
        if let Some(hwid) = std::env::var("WARDEN_HWID").ok().filter(|s| !s.is_empty()) {
            headers.insert(lc!("X-HWID").parse::<HeaderName>()?, HeaderValue::from_str(&hwid)?);
        }
        // связать→ разбивает реверс-инжинирщику совсем не очевидно ("telemetry bridge")
        let http = ClientBuilder::new()
            .default_headers(headers)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .gzip(true).brotli(true).deflate(true).build()?;
        // скраб на детерминированные поля для непредсказуемости
        if config.subscription_endpoint.is_empty() {
            config.subscription_endpoint = lc!("/sub/{token}/all.txt").to_string();
        }
        Ok(Self {
            http,
            config: Arc::new(config),
            cache: RwLock::new(None),
            limiter: Semaphore::new(10),
            last_req: RwLock::new(Instant::now()),
        })
    }

    pub async fn fetch_subscription(&self, token: &str) -> Result<Vec<ServerConfig>, WardenError> {
        let _p = self.limiter.acquire().await?;
        self.rate_limit().await;

        let endpoint = self.config.subscription_endpoint.replace("{token}", token);
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), endpoint);
        debug!("fetch: {}", url);

        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            error!("sub HTTP {}", resp.status());
            return Err(WardenError::Api(format!("HTTP {}", resp.status())));
        }

        let text = resp.text().await?;
        let configs = self.parse_subscription(&text)?;
        let cached = CachedSub { token: token.into(), configs: configs.clone(), fetched_at: chrono::Utc::now() };
        *self.cache.write().await = Some(cached);
        info!("fetched {} alive configs", configs.len());
        Ok(configs)
    }

    pub async fn cached(&self, token: &str) -> Option<Vec<ServerConfig>> {
        self.cache.read().await.as_ref()
            .filter(|c| c.token == token).map(|c| c.configs.clone())
    }

    async fn rate_limit(&self) {
        let mut last = self.last_req.write().await;
        let elapsed = last.elapsed();
        let min = Duration::from_millis(100);
        if elapsed < min { tokio::time::sleep(min - elapsed).await; }
        *last = Instant::now();
    }

    fn parse_subscription(&self, text: &str) -> Result<Vec<ServerConfig>, WardenError> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            if let Ok(url) = Url::parse(line) {
                let protocol = url.scheme().to_lowercase();
                let host = url.host_str().unwrap_or("").to_string();
                let port = url.port().unwrap_or(default_port(&protocol)) as i32;
                let region = url.fragment()
                    .and_then(|f| f.split(|c: char| !c.is_alphabetic()).find(|s| s.len() == 2))
                    .map(|s| s.to_uppercase());
                let id = hash_id(line);
                out.push(ServerConfig {
                    id, config_line: line.into(), protocol, host, port,
                    is_alive: true, source: None, health_score: Some(0.5),
                    response_time_ms: None, region,
                });
            }
        }
        Ok(out)
    }
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        "ss" => 8388,
        _ => 443,
    }
}

fn hash_id(s: &str) -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    (h.finish() & 0x7FFF_FFFF_FFFF_FFFF) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_known_schemes() {
        assert_eq!(default_port("https"), 443);
        assert_eq!(default_port("http"), 80);
        assert_eq!(default_port("ss"), 8388);
    }

    #[test]
    fn default_port_unknown_scheme() {
        assert_eq!(default_port("vless"), 443);
        assert_eq!(default_port("hysteria2"), 443);
        assert_eq!(default_port("wireguard"), 443);
    }

    #[test]
    fn hash_id_is_deterministic() {
        let id1 = hash_id("vless://user@host:443#DE");
        let id2 = hash_id("vless://user@host:443#DE");
        assert_eq!(id1, id2);
        assert!(id1 >= 0);
    }

    #[test]
    fn hash_id_different_inputs() {
        let id1 = hash_id("vless://user@host:443#DE");
        let id2 = hash_id("vless://user@other:443#DE");
        assert_ne!(id1, id2);
    }

    #[test]
    fn parse_subscription_basic_vless() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "vless://user@host.example.com:443?type=tcp#DE\n";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs.len(), 1);
        let cfg = &configs[0];
        assert_eq!(cfg.protocol, "vless");
        assert_eq!(cfg.host, "host.example.com");
        assert_eq!(cfg.port, 443);
        assert!(cfg.is_alive);
        assert_eq!(cfg.region, Some("DE".to_string()));
    }

    #[test]
    fn parse_subscription_skips_comments_and_blanks() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "# profile-title: Test Config\n\n# subscription-userinfo: upload=1024\nss://user@host:8388#US\n";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].protocol, "ss");
        assert_eq!(configs[0].port, 8388);
        assert_eq!(configs[0].region, Some("US".to_string()));
    }

    #[test]
    fn parse_subscription_multiple_protocols() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "\
vless://user@host1:443#DE
ss://user@host2:8388#US
hysteria2://user@host3:443#NL
wireguard://user@host4:51820#FR
";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs.len(), 4);
        assert_eq!(configs[0].protocol, "vless");
        assert_eq!(configs[1].protocol, "ss");
        assert_eq!(configs[2].protocol, "hysteria2");
        assert_eq!(configs[3].protocol, "wireguard");
    }

    #[test]
    fn parse_subscription_invalid_url_skipped() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "not-a-url-line\nvless://user@host:443#DE\n";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].protocol, "vless");
    }

    #[test]
    fn parse_subscription_empty_text() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let configs = api.parse_subscription("").unwrap();
        assert!(configs.is_empty());
    }

    #[test]
    fn parse_subscription_with_default_port() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "vless://user@host.example.com#DE\n";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].port, 443);
    }

    #[test]
    fn parse_subscription_explicit_port() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "vless://user@host.example.com:8443#DE\n";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs[0].port, 8443);
    }

    #[test]
    fn parse_subscription_region_extraction() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "vless://user@host:443#Region-DE-Profile\n";
        let configs = api.parse_subscription(text).unwrap();
        assert_eq!(configs[0].region, Some("DE".to_string()));
    }

    #[test]
    fn parse_subscription_no_region() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        let text = "vless://user@host:443\n";
        let configs = api.parse_subscription(text).unwrap();
        assert!(configs[0].region.is_none());
    }

    #[test]
    fn api_client_creates_with_defaults() {
        let cfg = ApiConfig::default();
        let _api = ApiClient::new(cfg).unwrap();
    }

    #[test]
    fn api_client_with_auth_token() {
        let mut cfg = ApiConfig::default();
        cfg.auth_token = Some(lc!("test-token"));
        let _api = ApiClient::new(cfg).unwrap();
    }

    #[test]
    fn api_client_with_hwid() {
        std::env::set_var("WARDEN_HWID", "test-hwid-123");
        let cfg = ApiConfig::default();
        let _api = ApiClient::new(cfg).unwrap();
        std::env::remove_var("WARDEN_HWID");
    }

    #[test]
    fn api_client_empty_endpoint_uses_default() {
        let mut cfg = ApiConfig::default();
        cfg.subscription_endpoint = String::new();
        let _api = ApiClient::new(cfg).unwrap();
    }

    #[test]
    fn server_config_deserialize() {
        let json = r#"{
            "id": 42,
            "config_line": "vless://user@host:443#DE",
            "protocol": "vless",
            "host": "host",
            "port": 443,
            "is_alive": true,
            "source": "clash",
            "health_score": 0.95,
            "response_time_ms": 120,
            "region": "DE"
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.id, 42);
        assert_eq!(cfg.protocol, "vless");
        assert_eq!(cfg.host, "host");
        assert_eq!(cfg.port, 443);
        assert!(cfg.is_alive);
        assert_eq!(cfg.source, Some("clash".to_string()));
        assert!((cfg.health_score.unwrap() - 0.95).abs() < 0.001);
        assert_eq!(cfg.response_time_ms, Some(120));
        assert_eq!(cfg.region, Some("DE".to_string()));
    }

    #[test]
    fn server_config_deserialize_defaults() {
        let json = r#"{
            "id": 1,
            "config_line": "vless://user@host:443#US",
            "protocol": "vless",
            "host": "host",
            "port": 443,
            "is_alive": false
        }"#;
        let cfg: ServerConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.is_alive);
        assert!(cfg.source.is_none());
        assert!(cfg.health_score.is_none());
        assert!(cfg.response_time_ms.is_none());
        assert!(cfg.region.is_none());
    }

    #[tokio::test]
    async fn cached_returns_none_initially() {
        let api = ApiClient::new(ApiConfig::default()).unwrap();
        assert!(api.cached("token").await.is_none());
    }
}
