use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::tun::Tun;
use crate::error::WardenError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::thread_rng;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use url::Url;

#[derive(Debug, Clone)]
pub struct WireguardConfig {
    pub public_key: [u8; 32],
    pub endpoint: SocketAddr,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Failed,
}

pub struct WireGuardTunnel {
    tunn: Arc<Mutex<boringtun::noise::Tunn>>,
    socket: Arc<UdpSocket>,
    config: WireguardConfig,
    state: Arc<Mutex<TunnelState>>,
    handshake_at: Arc<Mutex<Instant>>,
    tx_bytes: Arc<Mutex<u64>>,
    rx_bytes: Arc<Mutex<u64>>,
}

impl WireGuardTunnel {
    pub async fn from_share_url(url: &str) -> Result<Self, WardenError> {
        if !url.starts_with("wg://") {
            return Err(WardenError::ProtocolNotSupported(url.to_string()));
        }
        let parsed = Url::parse(url)?;
        let host = parsed
            .host_str()
            .ok_or_else(|| WardenError::TunnelError("missing host".into()))?;
        let port = parsed.port().unwrap_or(51820);
        let endpoint: SocketAddr = format!("{}:{}", host, port)
            .parse::<std::net::SocketAddr>()
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;

        let mut public_key = [0u8; 32];
        let username = parsed.username();
        let decoded = STANDARD
            .decode(username)
            .map_err(|e| WardenError::TunnelError(format!("bad pubkey: {}", e)))?;
        if decoded.len() != 32 {
            return Err(WardenError::TunnelError(
                "public key must be 32 bytes".into(),
            ));
        }
        public_key.copy_from_slice(&decoded);

        let mut allowed_ips = vec![];
        let mut persistent_keepalive = 25u16;
        for (k, v) in parsed.query_pairs() {
            match k.as_ref() {
                "allowed_ips" => allowed_ips = v.split(',').map(|s| s.trim().to_string()).collect(),
                "persistent_keepalive" => {
                    persistent_keepalive = v
                        .parse::<u16>()
                        .map_err(|e| WardenError::TunnelError(e.to_string()))?
                }
                _ => {}
            }
        }

        let peer_public = boringtun::x25519::PublicKey::from(public_key);
        let my_secret = boringtun::x25519::StaticSecret::random_from_rng(thread_rng());
        let tunn = boringtun::noise::Tunn::new(
            my_secret,
            peer_public,
            None,
            Some(persistent_keepalive),
            0,
            None,
        );

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;
        socket
            .connect(&endpoint)
            .await
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;

        let config = WireguardConfig {
            public_key,
            endpoint,
            allowed_ips,
            persistent_keepalive,
        };

        Ok(Self {
            tunn: Arc::new(Mutex::new(tunn)),
            socket: Arc::new(socket),
            config,
            state: Arc::new(Mutex::new(TunnelState::Disconnected)),
            handshake_at: Arc::new(Mutex::new(Instant::now())),
            tx_bytes: Arc::new(Mutex::new(0)),
            rx_bytes: Arc::new(Mutex::new(0)),
        })
    }

    pub async fn handshake(&mut self) -> Result<(), WardenError> {
        let mut state = self.state.lock().await;
        *state = TunnelState::Connecting;
        drop(state);

        info!(
            "wg handshake start {}:{}",
            self.config.endpoint.ip(),
            self.config.endpoint.port()
        );

        let mut tun = self.tunn.lock().await;
        let mut net_buf = [0u8; 2048];
        let result = tun.format_handshake_initiation(&mut net_buf, false);
        let init_packet = match result {
            boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            boringtun::noise::TunnResult::Err(e) => {
                return Err(WardenError::TunnelError(format!("{:?}", e)))
            }
            _ => return Err(WardenError::TunnelError("unexpected init result".into())),
        };
        drop(tun);

        self.socket
            .send(&init_packet)
            .await
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;

        let mut resp_buf = [0u8; 2048];
        let (n, _) = self
            .socket
            .recv_from(&mut resp_buf)
            .await
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;

        let mut tun = self.tunn.lock().await;
        let result = tun.decapsulate(
            Some(self.config.endpoint.ip()),
            &resp_buf[..n],
            &mut net_buf,
        );
        let resp_packet = match result {
            boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
            boringtun::noise::TunnResult::Err(e) => {
                return Err(WardenError::TunnelError(format!("{:?}", e)))
            }
            _ => return Err(WardenError::TunnelError("unexpected resp result".into())),
        };
        drop(tun);

        self.socket
            .send(&resp_packet)
            .await
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;

        let mut ka_buf = [0u8; 2048];
        let (n, _) = self
            .socket
            .recv_from(&mut ka_buf)
            .await
            .map_err(|e| WardenError::TunnelError(e.to_string()))?;

        let mut tun = self.tunn.lock().await;
        let result = tun.decapsulate(Some(self.config.endpoint.ip()), &ka_buf[..n], &mut net_buf);
        match result {
            boringtun::noise::TunnResult::Done => {
                *self.state.lock().await = TunnelState::Connected;
                *self.handshake_at.lock().await = Instant::now();
                info!("wg handshake complete");
                Ok(())
            }
            boringtun::noise::TunnResult::Err(e) => {
                Err(WardenError::TunnelError(format!("{:?}", e)))
            }
            _ => Err(WardenError::TunnelError(
                "unexpected keepalive result".into(),
            )),
        }
    }

    pub async fn run(&mut self, tun_fd: &mut dyn Tun) -> Result<(), WardenError> {
        let mut net_buf = [0u8; 2048];
        let mut tun_buf = [0u8; 2048];
        let ka_interval = self.config.persistent_keepalive;
        let mut ka_timer = Instant::now();

        loop {
            tokio::select! {
                res = self.socket.recv_from(&mut net_buf), if *self.state.lock().await == TunnelState::Connected => {
                    match res {
                        Ok((n, _)) => {
                            let mut tun = self.tunn.lock().await;
                            let mut dst = [0u8; 2048];
                            let result = tun.decapsulate(None, &net_buf[..n], &mut dst);
                            match result {
                                boringtun::noise::TunnResult::WriteToTunnelV4(pkt, _) |
                                boringtun::noise::TunnResult::WriteToTunnelV6(pkt, _) => {
                                    *self.rx_bytes.lock().await += pkt.len() as u64;
                                    drop(tun);
                                    if let Err(e) = tun_fd.write(pkt).await {
                                        warn!("tun write: {}", e);
                                    }
                                }
                                boringtun::noise::TunnResult::Done => {}
                                boringtun::noise::TunnResult::Err(e) => debug!("decapsulate: {:?}", e),
                                _ => {}
                            }
                        }
                        Err(e) => warn!("socket recv: {}", e),
                    }
                }
                res = tun_fd.read(&mut tun_buf), if *self.state.lock().await == TunnelState::Connected => {
                    match res {
                        Ok(n) => {
                            let mut tun = self.tunn.lock().await;
                            let mut dst = [0u8; 2048];
                            let result = tun.encapsulate(&tun_buf[..n], &mut dst);
                            match result {
                                boringtun::noise::TunnResult::WriteToNetwork(pkt) => {
                                    *self.tx_bytes.lock().await += n as u64;
                                    drop(tun);
                                    if let Err(e) = self.socket.send(pkt).await {
                                        warn!("socket send: {}", e);
                                    }
                                }
                                boringtun::noise::TunnResult::Err(e) => debug!("encapsulate: {:?}", e),
                                _ => {}
                            }
                        }
                        Err(e) => warn!("tun read: {}", e),
                    }
                }
                _ = sleep(Duration::from_secs(1)), if *self.state.lock().await == TunnelState::Connected => {
                    if ka_timer.elapsed() > Duration::from_secs(ka_interval as u64) {
                        ka_timer = Instant::now();
                        let mut tun = self.tunn.lock().await;
                        let mut dst = [0u8; 2048];
                        if let boringtun::noise::TunnResult::WriteToNetwork(pkt) = tun.format_handshake_initiation(&mut dst, false) {
                            drop(tun);
                            let _ = self.socket.send(pkt).await;
                        }
                    }
                }
            }
        }
    }

    pub fn read(&self) -> Option<DecodedPacket> {
        None
    }

    pub async fn state(&self) -> TunnelState {
        *self.state.lock().await
    }

    pub async fn stats(&self) -> (u64, u64) {
        (*self.tx_bytes.lock().await, *self.rx_bytes.lock().await)
    }
}

#[derive(Debug, Clone)]
pub struct DecodedPacket {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub payload: Vec<u8>,
}

pub struct WireGuardTunnelHandle {
    pub session_id: String,
    pub config: WireguardConfig,
}

impl WireGuardTunnelHandle {
    pub fn new(session_id: String, config: WireguardConfig) -> Self {
        Self { session_id, config }
    }

    pub async fn connect(self) -> Result<WireGuardTunnel, WardenError> {
        let mut tunnel = WireGuardTunnel::from_share_url(&format!(
            "wg://{}@{}:{}?allowed_ips={}&persistent_keepalive={}",
            STANDARD.encode(self.config.public_key),
            self.config.endpoint.ip(),
            self.config.endpoint.port(),
            self.config.allowed_ips.join(","),
            self.config.persistent_keepalive,
        ))
        .await?;
        tunnel.handshake().await?;
        Ok(tunnel)
    }
}

fn proof_payload() -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 0x45;
    p[1] = 0x00;
    p[2..4].copy_from_slice(&32u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&[10, 0, 0, 1]);
    p[16..20].copy_from_slice(&[10, 0, 0, 2]);
    p[20..22].copy_from_slice(&12345u16.to_be_bytes());
    p[22..24].copy_from_slice(&54321u16.to_be_bytes());
    p[24..32].copy_from_slice(&[0xABu8; 8]);
    p
}

/// Run a full WireGuard handshake + data round-trip over loopback UDP and
/// return the per-tunnel byte counters. Returns `None` on any failure so
/// callers (self-test) can report a clean false-negative-free result instead
/// of panicking mid-flight.
pub async fn loopback_handshake_proof() -> Option<(u64, u64, u64, u64)> {
    use boringtun::x25519;
    use rand::rngs::OsRng;

    let a_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let a_public = x25519::PublicKey::from(&a_secret);
    let b_secret = x25519::StaticSecret::random_from_rng(OsRng);
    let b_public = x25519::PublicKey::from(&b_secret);

    let mut a_tun = boringtun::noise::Tunn::new(a_secret, b_public, None, Some(25), 0, None);
    let mut b_tun = boringtun::noise::Tunn::new(b_secret, a_public, None, Some(25), 1, None);

    let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let a_addr = a_socket.local_addr().ok()?;
    let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let b_addr = b_socket.local_addr().ok()?;

    let mut net_buf = [0u8; 2048];
    let mut out_buf = [0u8; 2048];
    let mut recv = [0u8; 2048];

    let result = a_tun.format_handshake_initiation(&mut net_buf, false);
    let packet = match result {
        boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        _ => return None,
    };
    a_socket.send_to(&packet, b_addr).await.ok()?;

    let (n, _) = b_socket.recv_from(&mut recv).await.ok()?;
    let result = b_tun.decapsulate(Some(a_addr.ip()), &recv[..n], &mut out_buf);
    let init_resp = match result {
        boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        _ => return None,
    };
    b_socket.send_to(&init_resp, a_addr).await.ok()?;

    let (n, _) = a_socket.recv_from(&mut recv).await.ok()?;
    let result = a_tun.decapsulate(Some(b_addr.ip()), &recv[..n], &mut out_buf);
    match result {
        boringtun::noise::TunnResult::WriteToNetwork(pkt) => {
            a_socket.send_to(pkt, b_addr).await.ok()?;
        }
        _ => return None,
    }

    let (n, _) = b_socket.recv_from(&mut recv).await.ok()?;
    let result = b_tun.decapsulate(Some(a_addr.ip()), &recv[..n], &mut out_buf);
    if !matches!(result, boringtun::noise::TunnResult::Done) {
        return None;
    }

    let result = a_tun.encapsulate(&proof_payload(), &mut net_buf);
    let packet = match result {
        boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        _ => return None,
    };
    out_buf = [0u8; 2048];

    a_socket.send_to(&packet, b_addr).await.ok()?;

    let (n, _) = b_socket.recv_from(&mut recv).await.ok()?;
    let result = b_tun.decapsulate(Some(a_addr.ip()), &recv[..n], &mut out_buf);
    let reply = match result {
        boringtun::noise::TunnResult::WriteToTunnelV4(pkt, _)
        | boringtun::noise::TunnResult::WriteToTunnelV6(pkt, _) => pkt.to_vec(),
        _ => return None,
    };
    if reply != proof_payload().to_vec() {
        return None;
    }

    let result = b_tun.encapsulate(&reply, &mut net_buf);
    let packet = match result {
        boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
        _ => return None,
    };
    b_socket.send_to(&packet, a_addr).await.ok()?;

    let (n, _) = a_socket.recv_from(&mut recv).await.ok()?;
    let result = a_tun.decapsulate(Some(b_addr.ip()), &recv[..n], &mut out_buf);
    let reply2 = match result {
        boringtun::noise::TunnResult::WriteToTunnelV4(pkt, _)
        | boringtun::noise::TunnResult::WriteToTunnelV6(pkt, _) => pkt.to_vec(),
        _ => return None,
    };
    if reply2 != proof_payload().to_vec() {
        return None;
    }

    Some((
        a_tun.stats().1 as u64,
        a_tun.stats().2 as u64,
        b_tun.stats().1 as u64,
        b_tun.stats().2 as u64,
    ))
}

#[cfg(test)]
mod loopback {
    use super::*;
    use boringtun::x25519;
    use rand::rngs::OsRng;

    fn make_ipv4_udp_payload() -> [u8; 32] {
        let mut p = [0u8; 32];
        p[0] = 0x45;
        p[1] = 0x00;
        p[2..4].copy_from_slice(&32u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&12345u16.to_be_bytes());
        p[22..24].copy_from_slice(&54321u16.to_be_bytes());
        p[24..32].copy_from_slice(&[0xABu8; 8]);
        p
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn loopback_handshake_and_data() {
        let a_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let a_public = x25519::PublicKey::from(&a_secret);
        let b_secret = x25519::StaticSecret::random_from_rng(OsRng);
        let b_public = x25519::PublicKey::from(&b_secret);

        let mut a_tun = boringtun::noise::Tunn::new(a_secret, b_public, None, Some(25), 0, None);
        let mut b_tun = boringtun::noise::Tunn::new(b_secret, a_public, None, Some(25), 1, None);

        let a_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a_socket.local_addr().unwrap();
        let b_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_addr = b_socket.local_addr().unwrap();

        let a_handle = tokio::spawn(async move {
            let mut net_buf = [0u8; 2048];
            let mut out_buf = [0u8; 2048];
            let result = a_tun.format_handshake_initiation(&mut net_buf, false);
            let packet = match result {
                boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
                _ => panic!("a init failed"),
            };
            a_socket.send_to(&packet, b_addr).await.unwrap();

            let mut recv = [0u8; 2048];
            let (n, _) = a_socket.recv_from(&mut recv).await.unwrap();
            let result = a_tun.decapsulate(Some(b_addr.ip()), &recv[..n], &mut out_buf);
            let packet = match result {
                boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
                _ => panic!("a resp failed {:?}", result),
            };
            a_socket.send_to(&packet, b_addr).await.unwrap();

            let payload = make_ipv4_udp_payload();
            let result = a_tun.encapsulate(&payload, &mut net_buf);
            let packet = match result {
                boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
                _ => panic!("a data encapsulate failed {:?}", result),
            };
            a_socket.send_to(&packet, b_addr).await.unwrap();

            let (n, _) = a_socket.recv_from(&mut recv).await.unwrap();
            let result = a_tun.decapsulate(Some(b_addr.ip()), &recv[..n], &mut out_buf);
            let reply = match result {
                boringtun::noise::TunnResult::WriteToTunnelV4(pkt, _)
                | boringtun::noise::TunnResult::WriteToTunnelV6(pkt, _) => pkt.to_vec(),
                _ => panic!("a recv reply failed {:?}", result),
            };
            assert_eq!(reply, payload);
            a_tun
        });

        let b_handle = tokio::spawn(async move {
            let mut net_buf = [0u8; 2048];
            let mut out_buf = [0u8; 2048];
            let (n, _) = b_socket.recv_from(&mut net_buf).await.unwrap();
            let result = b_tun.decapsulate(Some(a_addr.ip()), &net_buf[..n], &mut out_buf);
            let init_resp = match result {
                boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
                _ => panic!("b init resp failed {:?}", result),
            };
            b_socket.send_to(&init_resp, a_addr).await.unwrap();

            let (n, _) = b_socket.recv_from(&mut net_buf).await.unwrap();
            let result = b_tun.decapsulate(Some(a_addr.ip()), &net_buf[..n], &mut out_buf);
            assert!(
                matches!(result, boringtun::noise::TunnResult::Done),
                "b response {:?}",
                result
            );

            let (n, _) = b_socket.recv_from(&mut net_buf).await.unwrap();
            let result = b_tun.decapsulate(Some(a_addr.ip()), &net_buf[..n], &mut out_buf);
            let data = match result {
                boringtun::noise::TunnResult::WriteToTunnelV4(pkt, _)
                | boringtun::noise::TunnResult::WriteToTunnelV6(pkt, _) => pkt.to_vec(),
                _ => panic!("b recv data failed {:?}", result),
            };
            assert_eq!(data, make_ipv4_udp_payload());

            let result = b_tun.encapsulate(&data, &mut net_buf);
            let packet = match result {
                boringtun::noise::TunnResult::WriteToNetwork(pkt) => pkt.to_vec(),
                _ => panic!("b data encapsulate failed {:?}", result),
            };
            b_socket.send_to(&packet, a_addr).await.unwrap();
            b_tun
        });

        let a_tun = a_handle.await.unwrap();
        let b_tun = b_handle.await.unwrap();

        let (_, a_tx, a_rx, _, _) = a_tun.stats();
        let (_, b_tx, b_rx, _, _) = b_tun.stats();

        println!("HANDSHAKE OK");
        println!("A tx={} rx={}", a_tx, a_rx);
        println!("B tx={} rx={}", b_tx, b_rx);
        assert!(a_tx > 0 && a_rx > 0 && b_tx > 0 && b_rx > 0);
    }
}
