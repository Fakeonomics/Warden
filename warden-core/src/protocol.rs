use std::collections::HashMap;
use std::time::Duration;

use crate::{
    api::ServerConfig,
    config::PerformanceMode,
    decision::{DecisionHook, ThreatContext},
    error::WardenError,
    hysteria2::Hy2Tunnel,
    protocol_helpers::{
        is_port_reachable, Hy2Params, SsParams, TrojanParams, VlessParams, VmessParams,
    },
    shadowsocks::SsTunnel,
    trojan::TrojanTunnel,
    tunnel::{WireGuardTunnelHandle, WireguardConfig},
    vless::VlessTunnel,
    vmess::VmessTunnel,
    ActiveConnection,
};
use chrono::Utc;
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

use crate::protocol_helpers::extract_wg_pubkey;

pub struct ProtocolManager {
    _config: crate::config::ProtocolsConfig,
    _api: std::sync::Arc<crate::api::ApiClient>,
    sessions: tokio::sync::RwLock<HashMap<String, SessionHandle>>,
    hook: std::sync::Arc<tokio::sync::RwLock<Box<dyn DecisionHook + Send + Sync>>>,
}

#[derive(Debug, Clone)]
struct SessionHandle {
    _id: String,
    _protocol: String,
    _host: String,
    _port: i32,
    _started_at: chrono::DateTime<chrono::Utc>,
    _fingerprint: String,
}

impl ProtocolManager {
    pub async fn new(
        config: crate::config::ProtocolsConfig,
        api: std::sync::Arc<crate::api::ApiClient>,
    ) -> Result<Self, WardenError> {
        Ok(Self {
            _config: config,
            _api: api,
            sessions: tokio::sync::RwLock::new(HashMap::new()),
            hook: std::sync::Arc::new(tokio::sync::RwLock::new(Box::new(
                crate::decision::NoopDecisionHook,
            ))),
        })
    }

    pub async fn set_hook(&self, hook: Box<dyn DecisionHook + Send + Sync>) {
        let mut h = self.hook.write().await;
        *h = hook;
    }

    /// Attempt to establish a single session from a ranked list of configs.
    ///
    /// Retries each candidate with exponential backoff, bounded by a total
    /// attempt budget. Never panics: every failure path returns `Ok(None)`
    /// so the caller can fall back gracefully when every candidate is dead.
    pub async fn try_connect(
        &self,
        prefer: &[String],
        exclude: &[String],
        operator: bool,
        configs: &[ServerConfig],
        mode: PerformanceMode,
    ) -> Result<Option<ActiveConnection>, WardenError> {
        let mut filtered_configs: Vec<ServerConfig> = configs.to_vec();
        if !exclude.is_empty() {
            filtered_configs.retain(|cfg| match &cfg.region {
                Some(r) => !exclude.contains(r),
                None => true,
            });
        }
        if !prefer.is_empty() {
            filtered_configs.sort_by(|a, b| {
                let a_pref = match &a.region {
                    Some(r) => prefer.contains(r),
                    None => false,
                };
                let b_pref = match &b.region {
                    Some(r) => prefer.contains(r),
                    None => false,
                };
                b_pref.cmp(&a_pref)
            });
        }
        let configs_to_use = if filtered_configs.is_empty() && !configs.is_empty() {
            configs.to_vec()
        } else {
            filtered_configs
        };

        let ctx = ThreatContext {
            network: "unknown".into(),
            goal: "connect".into(),
            jurisdiction: None,
            battery: 100,
            operator_mode: operator,
            mode,
            configs: configs_to_use,
        };
        let ranked = self.hook.read().await.rank_protocols(&ctx);

        let max_attempts: usize = 3;
        let base_delay = Duration::from_millis(200);
        let max_delay = Duration::from_secs(2);

        for cfg in ranked.iter().take(5) {
            let mut last_err: Option<WardenError> = None;
            for attempt in 1..=max_attempts {
                match self.open_session(cfg).await {
                    Ok(conn) => {
                        let sid = conn.session_id.clone();
                        self.sessions.write().await.insert(
                            sid.clone(),
                            SessionHandle {
                                _id: sid,
                                _protocol: cfg.protocol.clone(),
                                _host: conn.host.clone(),
                                _port: conn.port,
                                _started_at: conn.connected_at,
                                _fingerprint: conn.protocol.clone(),
                            },
                        );
                        return Ok(Some(conn));
                    }
                    Err(e) => {
                        last_err = Some(e);
                        if attempt < max_attempts {
                            let delay = (base_delay * 2u32.pow(attempt as u32 - 1)).min(max_delay);
                            sleep(delay).await;
                        }
                    }
                }
            }
            if let Some(e) = last_err {
                warn!(
                    "{} -> {}:{} exhausted {} attempts: {:?}",
                    cfg.protocol, cfg.host, cfg.port, max_attempts, e
                );
            }
        }
        Ok(None)
    }

    async fn open_session(&self, cfg: &ServerConfig) -> Result<ActiveConnection, WardenError> {
        if !is_port_reachable(&cfg.host, cfg.port).await {
            return Err(WardenError::TunnelError(format!(
                "host {}:{} unreachable (TCP probe failed)",
                cfg.host, cfg.port
            )));
        }
        info!(
            "open {} {}:{} sid={}",
            cfg.protocol,
            cfg.host,
            cfg.port,
            &Uuid::new_v4().to_string()[..8]
        );

        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        match cfg.protocol.as_str() {
            "wireguard" | "wg" => self.open_wireguard(cfg, &session_id, now).await,
            "vless" => self.open_vless(cfg, &session_id, now).await,
            "trojan" => self.open_trojan(cfg, &session_id, now).await,
            "ss" | "shadowsocks" => self.open_shadowsocks(cfg, &session_id, now).await,
            "vmess" => self.open_vmess(cfg, &session_id, now).await,
            "hysteria2" | "hy2" => self.open_hysteria2(cfg, &session_id, now).await,
            other => Err(WardenError::ProtocolNotSupported(other.to_string())),
        }
    }

    async fn open_wireguard(
        &self,
        cfg: &ServerConfig,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<ActiveConnection, WardenError> {
        let endpoint: std::net::SocketAddr = format!("{}:{}", cfg.host, cfg.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| WardenError::TunnelError(e.to_string()))?;

        // Extract pubkey from config_line if it's a wg:// URL
        let public_key = extract_wg_pubkey(&cfg.config_line).unwrap_or([0u8; 32]);

        let wg_config = WireguardConfig {
            public_key,
            endpoint,
            allowed_ips: vec!["10.66.66.2/32".into()],
            persistent_keepalive: 25,
        };

        let handle = WireGuardTunnelHandle::new(Uuid::new_v4().to_string(), wg_config);
        let handshake_timeout = std::time::Duration::from_secs(
            std::env::var("WARDEN_HANDSHAKE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(5),
        );
        let mut tunnel = tokio::time::timeout(handshake_timeout, handle.connect())
            .await
            .map_err(|_| WardenError::TunnelError("handshake timed out".into()))??;

        self.apply_killswitch().await;
        spawn_tunnel_runner(tunnel, cfg.protocol.clone()).await;

        Ok(ActiveConnection {
            session_id: session_id.to_string(),
            protocol: "wireguard".into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    async fn open_vless(
        &self,
        cfg: &ServerConfig,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<ActiveConnection, WardenError> {
        let params = VlessParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port)?;
        let tunnel = crate::vless::VlessTunnel::connect(params).await?;
        self.apply_killswitch().await;
        spawn_tunnel_runner_vless(tunnel, cfg.protocol.clone()).await;

        Ok(ActiveConnection {
            session_id: session_id.to_string(),
            protocol: "vless".into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    async fn open_trojan(
        &self,
        cfg: &ServerConfig,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<ActiveConnection, WardenError> {
        let params = TrojanParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port)?;
        let tunnel = crate::trojan::TrojanTunnel::connect(params).await?;
        self.apply_killswitch().await;
        spawn_tunnel_runner_trojan(tunnel, cfg.protocol.clone()).await;

        Ok(ActiveConnection {
            session_id: session_id.to_string(),
            protocol: "trojan".into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    async fn open_shadowsocks(
        &self,
        cfg: &ServerConfig,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<ActiveConnection, WardenError> {
        let params = SsParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port)?;
        let tunnel = crate::shadowsocks::SsTunnel::connect(params).await?;
        self.apply_killswitch().await;
        spawn_tunnel_runner_ss(tunnel, cfg.protocol.clone()).await;

        Ok(ActiveConnection {
            session_id: session_id.to_string(),
            protocol: "ss".into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    async fn open_vmess(
        &self,
        cfg: &ServerConfig,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<ActiveConnection, WardenError> {
        let params = VmessParams::from_config_line(&cfg.config_line, &cfg.host, cfg.port)?;
        let tunnel = crate::vmess::VmessTunnel::connect(params).await?;
        self.apply_killswitch().await;
        spawn_tunnel_runner_vmess(tunnel, cfg.protocol.clone()).await;

        Ok(ActiveConnection {
            session_id: session_id.to_string(),
            protocol: "vmess".into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    async fn open_hysteria2(
        &self,
        cfg: &ServerConfig,
        session_id: &str,
        now: chrono::DateTime<Utc>,
    ) -> Result<ActiveConnection, WardenError> {
        let params = Hy2Params::from_config_line(&cfg.config_line, &cfg.host, cfg.port)?;
        let tunnel = crate::hysteria2::Hy2Tunnel::connect(params).await?;
        self.apply_killswitch().await;
        spawn_tunnel_runner_hy2(tunnel, cfg.protocol.clone()).await;

        Ok(ActiveConnection {
            session_id: session_id.to_string(),
            protocol: "hysteria2".into(),
            server: format!("{}:{}", cfg.host, cfg.port),
            host: cfg.host.clone(),
            port: cfg.port,
            connected_at: now,
            bytes_sent: 0,
            bytes_received: 0,
        })
    }

    pub async fn disconnect(&self, session_id: &str) -> Result<(), WardenError> {
        self.sessions.write().await.remove(session_id);
        self.remove_killswitch().await;
        Ok(())
    }

    pub async fn list(&self) -> Vec<String> {
        self.sessions.read().await.keys().cloned().collect()
    }

    async fn apply_killswitch(&self) {
        let _ = tokio::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-o", "warden0", "-j", "ACCEPT"])
            .output()
            .await;
        let _ = tokio::process::Command::new("iptables")
            .args(["-A", "OUTPUT", "-d", "10.66.66.2/32", "-j", "ACCEPT"])
            .output()
            .await;
    }

    async fn remove_killswitch(&self) {
        let _ = tokio::process::Command::new("iptables")
            .args(["-D", "OUTPUT", "-o", "warden0", "-j", "ACCEPT"])
            .output()
            .await;
        let _ = tokio::process::Command::new("iptables")
            .args(["-D", "OUTPUT", "-d", "10.66.66.2/32", "-j", "ACCEPT"])
            .output()
            .await;
    }
}

async fn spawn_tunnel_runner(mut tunnel: crate::tunnel::WireGuardTunnel, _protocol: String) {
    tokio::spawn(async move {
        let mut tun_opt = super::tun::try_open_tun().await;
        loop {
            if let Some(ref mut tun) = tun_opt {
                if let Err(e) = tunnel.run(tun).await {
                    warn!("tunnel run error: {:?}", e);
                    tun_opt = super::tun::try_open_tun().await;
                }
            } else {
                sleep(Duration::from_secs(1)).await;
                tun_opt = super::tun::try_open_tun().await;
            }
        }
    });
}

async fn spawn_tunnel_runner_vless(tunnel: VlessTunnel, _protocol: String) {
    tokio::spawn(async move {
        let mut tun_opt = super::tun::try_open_tun().await;
        if let Some(tun) = tun_opt.as_mut() {
            let _ = tunnel.run_proxy(tun).await;
        } else {
            sleep(Duration::from_secs(1)).await;
        }
    });
}

async fn spawn_tunnel_runner_trojan(tunnel: TrojanTunnel, _protocol: String) {
    tokio::spawn(async move {
        let _ = tunnel.run_proxy().await;
    });
}

async fn spawn_tunnel_runner_ss(tunnel: SsTunnel, _protocol: String) {
    tokio::spawn(async move {
        let _ = tunnel.run_proxy().await;
    });
}

async fn spawn_tunnel_runner_vmess(tunnel: VmessTunnel, _protocol: String) {
    tokio::spawn(async move {
        let _ = tunnel.run_proxy().await;
    });
}

async fn spawn_tunnel_runner_hy2(tunnel: Hy2Tunnel, _protocol: String) {
    tokio::spawn(async move {
        let _ = tunnel.run_proxy().await;
    });
}
