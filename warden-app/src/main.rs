use warden_core::{Warden, WardenConfig};
use std::time::Duration;
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "warden=info,reqwest=warn".into()))
        .init();

    let config = WardenConfig::load()?;
    info!("Warden booting — api={}", config.api.base_url);

    let warden = Warden::new(config).await?;

    let token = std::env::var("WARDEN_TOKEN").unwrap_or_else(|_| "test".into());

    // One-click connect: pick best alive config from our VPN-Service subscription
    match warden.connect_best(&token).await {
        Ok(conn) => {
            info!("CONNECTED via {} → {}:{} (sid={})",
                conn.protocol, conn.host, conn.port, &conn.session_id[..8]);
            println!("✅ Connected via {} to {}:{}", conn.protocol, conn.host, conn.port);

            // Keep alive, rotate every N seconds
            loop {
                tokio::time::sleep(Duration::from_secs(warden.config.rotation.interval_seconds)).await;
                if let Some(s) = warden.status().await {
                    info!("Up {}s · {} bytes ↑↓", (chrono::Utc::now() - s.connected_at).num_seconds(), s.bytes_sent + s.bytes_received);
                } else {
                    info!("Session lost — auto-reconnecting");
                    if let Err(e) = warden.connect_best(&token).await {
                        error!("Reconnect failed: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
        Err(e) => {
            error!("Connection failed: {:?}", e);
            println!("❌ Connection failed: {:?}", e);
            std::process::exit(1);
        }
    }
}
