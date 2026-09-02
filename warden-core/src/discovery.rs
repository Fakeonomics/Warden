use crate::api::ServerConfig;
use crate::error::WardenError;
use reqwest::Client;
use std::collections::HashSet;
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct DiscoverySource {
    pub name: String,
    pub url: String,
    pub format: SourceFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFormat {
    Base64,
    Plain,
    MultiBase64,
}

pub fn default_sources() -> Vec<DiscoverySource> {
    vec![
        DiscoverySource { name: "all".into(), url: "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/configs_base64.txt".into(), format: SourceFormat::Base64 },
        DiscoverySource { name: "vless".into(), url: "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/vless_base64.txt".into(), format: SourceFormat::Base64 },
        DiscoverySource { name: "trojan".into(), url: "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/trojan_base64.txt".into(), format: SourceFormat::Base64 },
        DiscoverySource { name: "ss".into(), url: "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/protocols/shadowsocks_base64.txt".into(), format: SourceFormat::Base64 },
    ]
}

#[derive(Debug, Clone)]
pub struct DiscoveryEngine {
    pub sources: Vec<DiscoverySource>,
    pub timeout: Duration,
}

impl DiscoveryEngine {
    pub fn new(sources: Vec<DiscoverySource>) -> Self {
        Self {
            sources,
            timeout: Duration::from_secs(30),
        }
    }

    pub async fn discover(&self) -> Result<Vec<ServerConfig>, WardenError> {
        let mut all = Vec::new();
        for src in &self.sources {
            match self.fetch_source(src).await {
                Ok(configs) => {
                    info!("discovered source={} count={}", src.name, configs.len());
                    all.extend(configs);
                }
                Err(e) => warn!("discovery source={} failed: {}", src.name, e),
            }
        }
        let raw_len = all.len();
        let filtered = self.filter_protocols(all);
        let deduped = self.deduplicate(filtered);
        info!(
            "discovery complete: raw={}, unique={}",
            raw_len,
            deduped.len()
        );
        Ok(deduped)
    }

    async fn fetch_source(&self, src: &DiscoverySource) -> Result<Vec<ServerConfig>, WardenError> {
        // Transient feed failures (5xx, DNS hiccups, timeouts) are retried with
        // exponential backoff before giving up, so a single bad moment doesn't
        // wipe out the whole discovery batch.
        let max_attempts: u32 = 3;
        let base_delay = std::time::Duration::from_millis(200);
        let max_delay = std::time::Duration::from_secs(2);

        let mut last_err: Option<WardenError> = None;
        for attempt in 1..=max_attempts {
            match self.fetch_source_once(src).await {
                Ok(configs) => return Ok(configs),
                Err(e) => {
                    last_err = Some(e);
                    if attempt < max_attempts {
                        let delay = (base_delay * 2u32.pow(attempt - 1)).min(max_delay);
                        warn!(
                            "discovery source={} attempt {}/{} failed ({:?}), retrying in {:?}",
                            src.name,
                            attempt,
                            max_attempts,
                            last_err.as_ref().unwrap(),
                            delay
                        );
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| WardenError::Api("discovery failed".into())))
    }

    async fn fetch_source_once(
        &self,
        src: &DiscoverySource,
    ) -> Result<Vec<ServerConfig>, WardenError> {
        let client = Client::builder()
            .timeout(self.timeout)
            .gzip(true)
            .brotli(true)
            .build()
            .map_err(|e| WardenError::Api(e.to_string()))?;
        let resp = client.get(&src.url).send().await?;
        if !resp.status().is_success() {
            return Err(WardenError::Api(format!("HTTP {}", resp.status())));
        }
        let text = resp.text().await?;
        let lines = decode_source(&text, &src.format);
        let mut configs: Vec<ServerConfig> = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(cfg) = parse_config_line(line) {
                configs.push(cfg);
            }
        }
        Ok(configs)
    }

    fn filter_protocols(&self, configs: Vec<ServerConfig>) -> Vec<ServerConfig> {
        let allowed = ["vless", "trojan", "ss", "vmess", "hysteria2", "wireguard"];
        configs
            .into_iter()
            .filter(|c| allowed.contains(&c.protocol.as_str()))
            .filter(|c| c.is_alive)
            .collect()
    }

    fn deduplicate(&self, configs: Vec<ServerConfig>) -> Vec<ServerConfig> {
        let mut seen_line: HashSet<String> = HashSet::new();
        let mut seen_key: HashSet<(String, i32, String)> = HashSet::new();
        let mut out = Vec::new();
        for cfg in configs {
            let key = cfg.config_line.clone();
            if !key.is_empty() && !seen_line.contains(&key) {
                seen_line.insert(key);
                let composite = (cfg.host.clone(), cfg.port, cfg.protocol.clone());
                if !seen_key.contains(&composite) {
                    seen_key.insert(composite);
                    out.push(cfg);
                }
            }
        }
        out
    }
}

fn decode_source(text: &str, fmt: &SourceFormat) -> Vec<String> {
    match fmt {
        SourceFormat::Base64 => {
            if let Ok(decoded) =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text.trim())
            {
                if let Ok(s) = String::from_utf8(decoded) {
                    return s.lines().map(|l| l.to_string()).collect();
                }
            }
            text.lines().map(|l| l.to_string()).collect()
        }
        SourceFormat::MultiBase64 => text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                if let Ok(decoded) =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, line)
                {
                    if let Ok(s) = String::from_utf8(decoded) {
                        return Some(s);
                    }
                }
                Some(line.to_string())
            })
            .flat_map(|s| s.lines().map(|l| l.to_string()).collect::<Vec<_>>())
            .collect(),
        SourceFormat::Plain => text.lines().map(|l| l.to_string()).collect(),
    }
}

fn parse_config_line(line: &str) -> Result<ServerConfig, WardenError> {
    use url::Url;
    if let Ok(url) = Url::parse(line) {
        let protocol = url.scheme().to_lowercase();
        // Reject unknown protocols explicitly so garbage feeds don't silently
        // produce configs that later fail at connect time.
        if !matches!(
            protocol.as_str(),
            "vless" | "trojan" | "ss" | "vmess" | "hysteria2" | "wireguard" | "https" | "http"
        ) {
            return Err(WardenError::ConfigParseError(format!(
                "unsupported protocol: {protocol}"
            )));
        }
        let host = url.host_str().unwrap_or("").to_string();
        let port = url.port().unwrap_or(default_port(&protocol)) as i32;
        let region = parse_region_from_url(&url);
        let id = hash_config_id(line);
        return Ok(ServerConfig {
            id,
            config_line: line.into(),
            protocol,
            host,
            port,
            is_alive: true,
            source: Some("discovery_feed".into()),
            health_score: Some(0.5),
            response_time_ms: None,
            region,
        });
    }
    if line.starts_with("vmess://")
        || line.starts_with("vless://")
        || line.starts_with("ss://")
        || line.starts_with("trojan://")
        || line.starts_with("hysteria2://")
    {
        let protocol = line.split("://").next().unwrap_or("unknown").to_string();
        let id = hash_config_id(line);
        let (host, port) = extract_host_port_rough(line);
        return Ok(ServerConfig {
            id,
            config_line: line.into(),
            protocol,
            host,
            port,
            is_alive: true,
            source: Some("discovery_feed".into()),
            health_score: Some(0.5),
            response_time_ms: None,
            region: None,
        });
    }
    Err(WardenError::ConfigParseError(format!(
        "unknown line: {}",
        line
    )))
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "http" => 80,
        "ss" => 8388,
        "vless" => 443,
        "trojan" => 443,
        "vmess" => 443,
        "hysteria2" => 443,
        _ => 443,
    }
}

fn parse_region_from_url(url: &url::Url) -> Option<String> {
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

fn extract_host_port_rough(line: &str) -> (String, i32) {
    let mut host = "unknown".to_string();
    let mut port = 443i32;
    if let Some(at) = line.find('@') {
        let after = &line[at + 1..];
        if let Some(colon) = after.find(':') {
            host = after[..colon].to_string();
            if let Ok(p) = after[colon + 1..].parse::<i32>() {
                port = p;
            }
        } else {
            host = after.to_string();
        }
    }
    (host, port)
}

fn hash_config_id(s: &str) -> i64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    (hasher.finish() as i64) & 0x7FFF_FFFF_FFFF_FFFF
}

#[cfg(test)]
mod temp_real_feeds {
    use super::*;
    #[tokio::test]
    async fn discovery_real_feeds() {
        let engine = DiscoveryEngine::new(default_sources());
        let result = engine.discover().await;
        match result {
            Ok(configs) => {
                println!("REAL_FEEDS_FOUND={}", configs.len());
                for c in configs.iter().take(5) {
                    println!("REAL_FEED_LINE={}", c.config_line);
                }
            }
            Err(e) => {
                println!("REAL_FEEDS_ERROR={}", e);
            }
        }
    }
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn parse_known_protocols() {
        for line in [
            "vless://abc@1.2.3.4:443",
            "trojan://secret@host.example:443",
            "ss://base64payload@1.2.3.4:8388",
            "hysteria2://user@1.2.3.4:443",
            "wireguard://pubkey@1.2.3.4:51820",
        ] {
            let cfg = parse_config_line(line).expect("known protocol must parse");
            assert!(!cfg.host.is_empty(), "host must be non-empty for {line}");
            assert!(cfg.port > 0, "port must be positive for {line}");
        }
    }

    #[test]
    fn parse_unknown_protocol_is_error() {
        // Unknown scheme must not silently produce a config; it must error so
        // the caller can decide whether to drop or flag it.
        assert!(parse_config_line("ftp://1.2.3.4:21").is_err());
        assert!(parse_config_line("foo://1.2.3.4").is_err());
        assert!(parse_config_line("not a url at all").is_err());
        assert!(parse_config_line("").is_err());
    }

    #[test]
    fn parse_empty_malformed_lines() {
        assert!(parse_config_line("   ").is_err());
        assert!(parse_config_line("# comment").is_err());
        // A bare http URL parses but is not a VPN protocol — it is filtered
        // out later by filter_protocols, not by the parser.
        let cfg = parse_config_line("http://1.2.3.4").expect("http URL parses");
        assert_eq!(cfg.protocol, "http");
    }

    #[test]
    fn dedup_collapses_near_duplicates() {
        let engine = DiscoveryEngine::new(vec![]);
        let a = ServerConfig {
            id: 1,
            config_line: "vless://a@1.2.3.4:443".into(),
            protocol: "vless".into(),
            host: "1.2.3.4".into(),
            port: 443,
            is_alive: true,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        };
        let b = ServerConfig {
            id: 2,
            config_line: "vless://a@1.2.3.4:443?foo=bar".into(),
            protocol: "vless".into(),
            host: "1.2.3.4".into(),
            port: 443,
            is_alive: true,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        };
        let c = ServerConfig {
            id: 3,
            config_line: "trojan://x@5.6.7.8:443".into(),
            protocol: "trojan".into(),
            host: "5.6.7.8".into(),
            port: 443,
            is_alive: true,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        };
        let out = engine.deduplicate(vec![a, b, c]);
        assert_eq!(
            out.len(),
            2,
            "near-duplicate (same host/port/proto) must collapse"
        );
    }

    #[test]
    fn filter_protocols_unknown_dropped() {
        let engine = DiscoveryEngine::new(vec![]);
        let allowed = ServerConfig {
            id: 1,
            config_line: "vless://a@1.2.3.4:443".into(),
            protocol: "vless".into(),
            host: "1.2.3.4".into(),
            port: 443,
            is_alive: true,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        };
        let dead = ServerConfig {
            id: 2,
            config_line: "vless://b@1.2.3.5:443".into(),
            protocol: "vless".into(),
            host: "1.2.3.5".into(),
            port: 443,
            is_alive: false,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        };
        let unknown = ServerConfig {
            id: 3,
            config_line: "ftp://c@1.2.3.6:21".into(),
            protocol: "ftp".into(),
            host: "1.2.3.6".into(),
            port: 21,
            is_alive: true,
            source: None,
            health_score: None,
            response_time_ms: None,
            region: None,
        };
        let out = engine.filter_protocols(vec![allowed, dead, unknown]);
        assert_eq!(out.len(), 1, "only alive + allowed protocol survives");
        assert_eq!(out[0].host, "1.2.3.4");
    }

    #[test]
    fn decode_plain_and_multi_base64() {
        let plain = decode_source("line1\nline2\n# c\n", &SourceFormat::Plain);
        assert_eq!(plain, vec!["line1", "line2", "# c"]);

        // MultiBase64: each line is a base64 blob that decodes to one inner line.
        use base64::Engine as _;
        let inner = base64::engine::general_purpose::STANDARD.encode("inner-line");
        let multi = decode_source(&inner, &SourceFormat::MultiBase64);
        assert_eq!(multi, vec!["inner-line"]);
    }
}

pub async fn health_filter(
    _engine: DiscoveryEngine,
    configs: Vec<ServerConfig>,
) -> Vec<ServerConfig> {
    configs
        .into_iter()
        .filter(|c| c.is_alive)
        .filter(|c| c.health_score.unwrap_or(0.0) >= 0.0)
        .collect()
}
