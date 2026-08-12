use crate::{config::ApiConfig, error::WardenError};
use reqwest::{Client, ClientBuilder, header::{HeaderMap, HeaderValue, USER_AGENT}};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info, warn, error};
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
    fetched_at: chrono::DateTime<chrono::Utc>,
    etag: Option<String>,
}

impl ApiClient {
    pub fn new(config: ApiConfig) -> Result<Self, WardenError> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&config.user_agent)?);
        if let Some(t) = &config.auth_token {
            headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", t))?);
        }
        let http = ClientBuilder::new()
            .default_headers(headers)
            .timeout(Duration::from_secs(config.timeout_seconds))
            .gzip(true).brotli(true).build()?;
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
        debug!("Fetching subscription: {}", url);

        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            error!("Subscription HTTP {}", resp.status());
            return Err(WardenError::Api(format!("HTTP {}", resp.status())));
        }

        let text = resp.text().await?;
        let etag = None;
        let configs = self.parse_subscription(&text)?;

        let cached = CachedSub { token: token.into(), configs: configs.clone(), fetched_at: chrono::Utc::now(), etag };
        *self.cache.write().await = Some(cached);

        info!("Fetched {} alive configs", configs.len());
        Ok(configs)
    }

    pub async fn cached(&self, token: &str) -> Option<Vec<ServerConfig>> {
        let g = self.cache.read().await;
        g.as_ref().filter(|c| c.token == token).map(|c| c.configs.clone())
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
                let protocol = url.scheme().to_string();
                let host = url.host_str().unwrap_or("").to_string();
                let port = url.port().unwrap_or(443) as i32;
                let id = hash_id(line);
                out.push(ServerConfig {
                    id, config_line: line.into(), protocol, host, port,
                    is_alive: true, source: None, health_score: Some(0.5), response_time_ms: None,
                });
            }
        }
        Ok(out)
    }
}

fn hash_id(s: &str) -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    (h.finish() & 0x7FFF_FFFF_FFFF_FFFF) as i64
}
