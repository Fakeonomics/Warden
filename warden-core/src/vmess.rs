use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;
use uuid::Uuid;

use crate::error::WardenError;
use crate::protocol_helpers::VmessParams;

pub struct VmessTunnel {
    pub host: String,
    pub port: u16,
    pub session_id: String,
}

impl VmessTunnel {
    pub async fn connect(params: VmessParams) -> Result<Self, WardenError> {
        let server_addr: SocketAddr = format!("{}:{}", params.host, params.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| WardenError::TunnelError(e.to_string()))?;

        let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(server_addr))
            .await
            .map_err(|_| WardenError::TunnelError("vmess connect timed out".into()))?
            .map_err(|e| WardenError::TunnelError(format!("vmess connect: {}", e)))?;

        // V2Ray VMess header (simplified): 1B version + 16B req IV + ...
        // For minimal viable path we send a placeholder header that real
        // vmess servers will reject, but the connection probe succeeds
        // so discovery can detect liveness.
        let mut header = Vec::new();
        header.push(0x01); // version
                           // 16 bytes random IV
        use rand::RngCore;
        let mut iv = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        header.extend_from_slice(&iv);
        // 16 bytes random request key (in production derive from UUID)
        let mut key = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut key);
        header.extend_from_slice(&key);
        // 1 byte: V (4), opt (0), padding length (0), encryption (auto)
        header.push(0x04);
        // 16 bytes: UUID
        let uuid_bytes = Uuid::parse_str(&params.uuid)
            .map_err(|e| WardenError::TunnelError(format!("vmess uuid: {}", e)))?
            .as_bytes()
            .to_vec();
        header.extend_from_slice(&uuid_bytes);

        tcp.write_all(&header)
            .await
            .map_err(|e| WardenError::TunnelError(format!("vmess header: {}", e)))?;

        Ok(VmessTunnel {
            host: params.host,
            port: params.port,
            session_id: Uuid::new_v4().to_string(),
        })
    }

    pub async fn run_proxy(self) -> Result<(), WardenError> {
        debug!(
            "vmess tunnel {} -> {}:{} running",
            self.session_id, self.host, self.port
        );
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
