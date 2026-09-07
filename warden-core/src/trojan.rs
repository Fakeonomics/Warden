use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;
use uuid::Uuid;

use crate::error::WardenError;
use crate::protocol_helpers::TrojanParams;

pub struct TrojanTunnel {
    pub host: String,
    pub port: u16,
    pub session_id: String,
}

impl TrojanTunnel {
    pub async fn connect(params: TrojanParams) -> Result<Self, WardenError> {
        let server_addr: SocketAddr = format!("{}:{}", params.host, params.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| WardenError::TunnelError(e.to_string()))?;

        let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
            .await
            .map_err(|_| WardenError::TunnelError("trojan connect timed out".into()))?
            .map_err(|e| WardenError::TunnelError(format!("trojan connect: {}", e)))?;

        // Trojan handshake: hex(SHA224(password)) + "\r\n" + "CONNECT host:port HTTP/1.1\r\nHost: host\r\n\r\n"
        use sha2::{Digest, Sha224};
        let mut hasher = Sha224::new();
        hasher.update(params.password.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let mut handshake = Vec::new();
        handshake.extend_from_slice(hash.as_bytes());
        handshake.extend_from_slice(b"\r\n");

        // For minimal viable path, request CONNECT to SNI host
        let target = format!(
            "{}:443",
            params.sni.clone().unwrap_or_else(|| params.host.clone())
        );
        handshake.extend_from_slice(format!("CONNECT {} HTTP/1.1\r\n", target).as_bytes());
        handshake.extend_from_slice(format!("Host: {}\r\n", target).as_bytes());
        handshake.extend_from_slice(b"\r\n");

        let mut tcp = tcp;
        tcp.write_all(&handshake)
            .await
            .map_err(|e| WardenError::TunnelError(format!("trojan handshake: {}", e)))?;

        Ok(TrojanTunnel {
            host: params.host,
            port: params.port,
            session_id: Uuid::new_v4().to_string(),
        })
    }

    pub async fn run_proxy(self) -> Result<(), WardenError> {
        debug!(
            "trojan tunnel {} -> {}:{} running",
            self.session_id, self.host, self.port
        );
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
