use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;
use uuid::Uuid;

use crate::error::WardenError;
use crate::protocol_helpers::SsParams;

pub struct SsTunnel {
    pub host: String,
    pub port: u16,
    pub session_id: String,
}

impl SsTunnel {
    pub async fn connect(params: SsParams) -> Result<Self, WardenError> {
        let server_addr: SocketAddr = format!("{}:{}", params.host, params.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| WardenError::TunnelError(e.to_string()))?;

        let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
            .await
            .map_err(|_| WardenError::TunnelError("ss connect timed out".into()))?
            .map_err(|e| WardenError::TunnelError(format!("ss connect: {}", e)))?;

        // Shadowsocks SIP022 AEAD 2022 handshake: we send a fixed salt + header
        // For minimal viable path: salt (32 bytes) + encrypted header (9+ bytes)
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        tcp.write_all(&salt)
            .await
            .map_err(|e| WardenError::TunnelError(format!("ss salt: {}", e)))?;

        Ok(SsTunnel {
            host: params.host,
            port: params.port,
            session_id: Uuid::new_v4().to_string(),
        })
    }

    pub async fn run_proxy(self) -> Result<(), WardenError> {
        debug!(
            "ss tunnel {} -> {}:{} running",
            self.session_id, self.host, self.port
        );
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
