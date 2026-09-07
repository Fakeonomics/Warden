use std::net::SocketAddr;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use tokio::net::TcpStream;
use url::Url;

use crate::error::WardenError;

pub async fn is_port_reachable(host: &str, port: i32) -> bool {
    if host.is_empty() || port <= 0 || port > 65535 {
        return false;
    }
    let addr = match format!("{}:{}", host, port).parse::<SocketAddr>() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let timeout = Duration::from_secs(3);
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            true
        }
        _ => false,
    }
}

pub fn extract_wg_pubkey(config_line: &str) -> Option<[u8; 32]> {
    if !config_line.starts_with("wg://") && !config_line.starts_with("wireguard://") {
        return None;
    }
    let url = Url::parse(config_line).ok()?;
    let username = url.username();
    if username.is_empty() {
        return None;
    }
    let decoded = STANDARD.decode(username).ok()?;
    if decoded.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Some(key)
}

#[derive(Debug, Clone)]
pub struct VlessParams {
    pub host: String,
    pub port: u16,
    pub uuid: String,
    pub sni: Option<String>,
    pub flow: Option<String>,
    pub security: Option<String>,
    pub alpn: Vec<String>,
    pub fingerprint: Option<String>,
    pub network: Option<String>,
    pub path: Option<String>,
    pub host_header: Option<String>,
}

impl VlessParams {
    pub fn from_config_line(line: &str, host: &str, port: i32) -> Result<Self, WardenError> {
        if !line.starts_with("vless://") {
            return Err(WardenError::ConfigParseError("not a vless URL".into()));
        }
        let url = Url::parse(line)
            .map_err(|e| WardenError::ConfigParseError(format!("vless parse: {}", e)))?;
        let uuid = url.username().to_string();
        if uuid.is_empty() {
            return Err(WardenError::ConfigParseError("vless missing uuid".into()));
        }
        let query: std::collections::HashMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let alpn = query
            .get("alpn")
            .map(|s| s.split(',').map(|x| x.to_string()).collect())
            .unwrap_or_default();
        Ok(VlessParams {
            host: host.to_string(),
            port: port as u16,
            uuid,
            sni: query
                .get("sni")
                .cloned()
                .or_else(|| query.get("peer").cloned()),
            flow: query.get("flow").cloned(),
            security: query.get("security").cloned(),
            alpn,
            fingerprint: query.get("fp").cloned(),
            network: query.get("type").cloned(),
            path: query.get("path").cloned(),
            host_header: query.get("host").cloned(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct TrojanParams {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub skip_verify: bool,
}

impl TrojanParams {
    pub fn from_config_line(line: &str, host: &str, port: i32) -> Result<Self, WardenError> {
        if !line.starts_with("trojan://") {
            return Err(WardenError::ConfigParseError("not a trojan URL".into()));
        }
        let url = Url::parse(line)
            .map_err(|e| WardenError::ConfigParseError(format!("trojan parse: {}", e)))?;
        let password = url.username().to_string();
        if password.is_empty() {
            return Err(WardenError::ConfigParseError(
                "trojan missing password".into(),
            ));
        }
        let query: std::collections::HashMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let alpn = query
            .get("alpn")
            .map(|s| s.split(',').map(|x| x.to_string()).collect())
            .unwrap_or_default();
        let skip_verify = query
            .get("allowInsecure")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        Ok(TrojanParams {
            host: host.to_string(),
            port: port as u16,
            password,
            sni: query
                .get("sni")
                .cloned()
                .or_else(|| query.get("peer").cloned()),
            alpn,
            skip_verify,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SsParams {
    pub host: String,
    pub port: u16,
    pub method: String,
    pub password: String,
}

impl SsParams {
    pub fn from_config_line(line: &str, host: &str, port: i32) -> Result<Self, WardenError> {
        if !line.starts_with("ss://") {
            return Err(WardenError::ConfigParseError("not an ss URL".into()));
        }
        let url = Url::parse(line)
            .map_err(|e| WardenError::ConfigParseError(format!("ss parse: {}", e)))?;
        let userinfo = url.username();
        let decoded_userinfo = match STANDARD.decode(userinfo) {
            Ok(b) => b,
            Err(_) => userinfo.as_bytes().to_vec(),
        };
        let userinfo_str = String::from_utf8_lossy(&decoded_userinfo);
        let mut parts = userinfo_str.splitn(2, ':');
        let method = parts.next().unwrap_or("").to_string();
        let password = parts.next().unwrap_or("").to_string();
        if method.is_empty() || password.is_empty() {
            return Err(WardenError::ConfigParseError(
                "ss missing method/password".into(),
            ));
        }
        Ok(SsParams {
            host: host.to_string(),
            port: port as u16,
            method,
            password,
        })
    }
}

#[derive(Debug, Clone)]
pub struct VmessParams {
    pub host: String,
    pub port: u16,
    pub uuid: String,
    pub alter_id: i32,
    pub security: String,
    pub network: Option<String>,
    pub tls: bool,
    pub sni: Option<String>,
    pub path: Option<String>,
    pub host_header: Option<String>,
}

impl VmessParams {
    pub fn from_config_line(line: &str, host: &str, port: i32) -> Result<Self, WardenError> {
        if !line.starts_with("vmess://") {
            return Err(WardenError::ConfigParseError("not a vmess URL".into()));
        }
        let payload = line.trim_start_matches("vmess://");
        let decoded = STANDARD
            .decode(payload)
            .map_err(|e| WardenError::ConfigParseError(format!("vmess base64: {}", e)))?;
        let json: serde_json::Value = serde_json::from_slice(&decoded)
            .map_err(|e| WardenError::ConfigParseError(format!("vmess json: {}", e)))?;
        let uuid = json
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| WardenError::ConfigParseError("vmess missing id".into()))?
            .to_string();
        let alter_id = json
            .get("aid")
            .and_then(|v| v.as_i64())
            .map(|x| x as i32)
            .unwrap_or(0);
        let security = json
            .get("scy")
            .and_then(|v| v.as_str())
            .unwrap_or("auto")
            .to_string();
        let network = json
            .get("net")
            .and_then(|v| v.as_str())
            .map(|x| x.to_string());
        let tls = json
            .get("tls")
            .and_then(|v| v.as_str())
            .map(|s| s == "tls")
            .unwrap_or(false);
        let sni = json
            .get("sni")
            .and_then(|v| v.as_str())
            .map(|x| x.to_string());
        let path = json
            .get("path")
            .and_then(|v| v.as_str())
            .map(|x| x.to_string());
        let host_header = json
            .get("host")
            .and_then(|v| v.as_str())
            .map(|x| x.to_string());
        Ok(VmessParams {
            host: host.to_string(),
            port: port as u16,
            uuid,
            alter_id,
            security,
            network,
            tls,
            sni,
            path,
            host_header,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Hy2Params {
    pub host: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub obfs: Option<String>,
    pub alpn: Vec<String>,
    pub insecure: bool,
}

impl Hy2Params {
    pub fn from_config_line(line: &str, host: &str, port: i32) -> Result<Self, WardenError> {
        if !line.starts_with("hysteria2://") && !line.starts_with("hy2://") {
            return Err(WardenError::ConfigParseError("not a hysteria2 URL".into()));
        }
        let url = Url::parse(line)
            .map_err(|e| WardenError::ConfigParseError(format!("hy2 parse: {}", e)))?;
        let password = url.username().to_string();
        if password.is_empty() {
            return Err(WardenError::ConfigParseError("hy2 missing password".into()));
        }
        let query: std::collections::HashMap<_, _> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let alpn = query
            .get("alpn")
            .map(|s| s.split(',').map(|x| x.to_string()).collect())
            .unwrap_or_default();
        let insecure = query
            .get("insecure")
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        Ok(Hy2Params {
            host: host.to_string(),
            port: port as u16,
            password,
            sni: query.get("sni").cloned(),
            obfs: query.get("obfs").cloned(),
            alpn,
            insecure,
        })
    }
}
