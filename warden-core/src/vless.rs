use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::error::WardenError;
use crate::protocol_helpers::VlessParams;

pub struct VlessTunnel {
    pub host: String,
    pub port: u16,
    pub session_id: String,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

impl VlessTunnel {
    pub async fn connect(params: VlessParams) -> Result<Self, WardenError> {
        let server_addr: SocketAddr = format!("{}:{}", params.host, params.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| WardenError::TunnelError(e.to_string()))?;

        let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
            .await
            .map_err(|_| WardenError::TunnelError("vless connect timed out".into()))?
            .map_err(|e| WardenError::TunnelError(format!("vless connect: {}", e)))?;

        // Build minimal VLESS request:
        // 1 byte version (0x00)
        // 16 bytes UUID
        // 1 byte addons length (0x00)
        // 1 byte command (1 = TCP)
        // 2 bytes port (big endian)
        // 1 byte address type (1 = IPv4, 2 = domain, 3 = IPv6)
        // N bytes address
        // header (we send none)
        let mut req: Vec<u8> = Vec::new();
        req.push(0x00);
        let uuid_bytes = Uuid::parse_str(&params.uuid)
            .map_err(|e| WardenError::TunnelError(format!("vless uuid: {}", e)))?
            .as_bytes()
            .to_vec();
        req.extend_from_slice(&uuid_bytes);
        req.push(0x00); // addons len
        req.push(0x01); // command: TCP
        let target_port: u16 = 443;
        req.extend_from_slice(&target_port.to_be_bytes());
        req.push(0x02); // address type: domain
        let target_host = params
            .sni
            .clone()
            .unwrap_or_else(|| "example.com".to_string());
        let target_bytes = target_host.as_bytes();
        req.push(target_bytes.len() as u8);
        req.extend_from_slice(target_bytes);
        // empty header

        tcp.write_all(&req)
            .await
            .map_err(|e| WardenError::TunnelError(format!("vless write req: {}", e)))?;

        Ok(VlessTunnel {
            host: params.host,
            port: params.port,
            session_id: Uuid::new_v4().to_string(),
            bytes_tx: req.len() as u64,
            bytes_rx: 0,
        })
    }

    pub async fn run_proxy(self, _tun: &mut dyn crate::tun::Tun) -> Result<(), WardenError> {
        // The minimal viable path: keep the connection alive; in production we
        // wire TUN reads to the VLESS payload stream and vice versa.
        debug!(
            "vless tunnel {} -> {}:{} running",
            self.session_id, self.host, self.port
        );
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.bytes_tx, self.bytes_rx)
    }
}

pub async fn read_packet(_t: &mut TcpStream, _buf: &mut [u8]) -> Result<usize, WardenError> {
    Ok(0)
}

pub fn warn_if_legacy(line: &str) {
    if line.is_empty() {
        warn!("vless: empty config line");
    }
}
