use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;
use uuid::Uuid;

use crate::error::WardenError;
use crate::protocol_helpers::Hy2Params;

pub struct Hy2Tunnel {
    pub host: String,
    pub port: u16,
    pub session_id: String,
}

impl Hy2Tunnel {
    pub async fn connect(params: Hy2Params) -> Result<Self, WardenError> {
        let server_addr: SocketAddr = format!("{}:{}", params.host, params.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| WardenError::TunnelError(e.to_string()))?;

        let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
            .await
            .map_err(|_| WardenError::TunnelError("hy2 connect timed out".into()))?
            .map_err(|e| WardenError::TunnelError(format!("hy2 connect: {}", e)))?;

        // Hysteria2: QUIC-based. For a minimal viable path we send a
        // 16-byte salt (server-issued challenge) so the server can complete
        // its first auth step. Real hysteria2 uses QUIC handshake.
        use rand::RngCore;
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        tcp.write_all(&salt)
            .await
            .map_err(|e| WardenError::TunnelError(format!("hy2 salt: {}", e)))?;

        Ok(Hy2Tunnel {
            host: params.host,
            port: params.port,
            session_id: Uuid::new_v4().to_string(),
        })
    }

    pub async fn run_proxy(self) -> Result<(), WardenError> {
        debug!(
            "hy2 tunnel {} -> {}:{} running",
            self.session_id, self.host, self.port
        );
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
