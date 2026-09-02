use crate::{config::ApiConfig, error::WardenError};
use reqwest::{
    header::{HeaderMap, HeaderValue, USER_AGENT},
    Client, ClientBuilder,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, error, info};
use url::Url;
use uuid::Uuid;

fn uuid_namespace() -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_DNS, b"warden.fakeonomics.online")
}

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
    _fetched_at: chrono::DateTime<chrono::Utc>,
}

impl ApiClient {
    pub fn new(mut config: ApiConfig) -> Result<Self, WardenError> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&config.user_agent)?);
        if let Some(t) = &config.auth_token {
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&format!("Bearer {}", t))?,
            );
        }
        if std::env::var("WARDEN_HWID_OPT_IN").ok().as_deref() == Some("1") {
            if let Some(hwid) = std::env::var("WARDEN_HWID").ok().filter(|s| !s.is_empty()) {
                headers.insert("X-HWID", HeaderValue::from_str(&hwid)?);
            }
        }
        let http = ClientBuilder::new()
            .default_headers(headers)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .gzip(true)
            .brotli(true)
            .no_deflate()
            .build()?;
        if config.subscription_endpoint.is_empty() {
            config.subscription_endpoint = "/sub/{token}/all.txt".to_string();
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
        let _p = self
            .limiter
            .acquire()
            .await
            .map_err(|e| WardenError::AcquireError(e.to_string()))?;
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
        let cached = CachedSub {
            token: token.into(),
            configs: configs.clone(),
            _fetched_at: chrono::Utc::now(),
        };
        *self.cache.write().await = Some(cached);
        info!("fetched {} alive configs", configs.len());
        Ok(configs)
    }

    pub async fn cached(&self, token: &str) -> Option<Vec<ServerConfig>> {
        self.cache
            .read()
            .await
            .as_ref()
            .filter(|c| c.token == token)
            .map(|c| c.configs.clone())
    }

    async fn rate_limit(&self) {
        let mut last = self.last_req.write().await;
        let elapsed = last.elapsed();
        let min = Duration::from_millis(100);
        if elapsed < min {
            tokio::time::sleep(min - elapsed).await;
        }
        *last = Instant::now();
    }

    fn parse_subscription(&self, text: &str) -> Result<Vec<ServerConfig>, WardenError> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(url) = Url::parse(line) {
                let protocol = url.scheme().to_lowercase();
                let host = url.host_str().unwrap_or("").to_string();
                let port = url.port().unwrap_or(default_port(&protocol)) as i32;
                let region = parse_region(&url);
                let id = hash_id(line);
                out.push(ServerConfig {
                    id,
                    config_line: line.into(),
                    protocol,
                    host,
                    port,
                    is_alive: true,
                    source: None,
                    health_score: Some(0.5),
                    response_time_ms: None,
                    region,
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

fn parse_region(url: &Url) -> Option<String> {
    if let Some(frag) = url.fragment() {
        for pair in frag.split('&') {
            if let Some(rest) = pair.strip_prefix("region=") {
                let val = rest
                    .trim()
                    .chars()
                    .take(2)
                    .collect::<String>()
                    .to_uppercase();
                if val.len() == 2 && val.chars().all(|c| c.is_ascii_alphabetic()) {
                    return Some(val);
                }
            }
        }
    }
    for seg in url.path().split('/') {
        if seg.len() == 2 && seg.chars().all(|c| c.is_ascii_alphabetic()) {
            return Some(seg.to_uppercase());
        }
    }
    None
}

fn hash_id(s: &str) -> i64 {
    let uuid = Uuid::new_v5(&uuid_namespace(), s.as_bytes());
    let (lo, hi) = uuid.as_u64_pair();
    ((lo ^ hi) & 0x7FFF_FFFF_FFFF_FFFF) as i64
}
