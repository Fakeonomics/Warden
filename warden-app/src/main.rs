use warden_core::{Warden, WardenConfig, Mode};
use std::time::Duration;
use tracing::{info, error, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "warden=info,reqwest=warn".into()))
        .init();

    let mut config = WardenConfig::load()?;
    config.api.auth_token = std::env::var("WARDEN_TOKEN").ok();
    let token = std::env::var("WARDEN_TOKEN").unwrap_or_else(|_| "test".into());

    info!("warden booting mode={:?}", config.mode);
    let warden = Warden::new(config).await?;

    // auto-connect (civilian one-click)
    match warden.connect(&token).await {
        Ok(conn) => {
            info!("CONNECTED via {} → {}:{} (sid:{})", conn.protocol, conn.host, conn.port, &conn.session_id[..8]);
            println!("✅ Connected via {} to {}:{}", conn.protocol, conn.host, conn.port);

            // operator unlock if env provided (demo)
            if let Ok(code) = std::env::var("WARDEN_OP_CODE") {
                if warden.unlock_operator(&code).await {
                    println!("🔓 Operator mode unlocked");
                    let st = warden.opsec_status().await;
                    info!("opsec: fp={} hwid={} kill={}", st.current_fingerprint, &st.current_hwid[..8.min(st.current_hwid.len())], st.kill_switch);
                } else {
                    warn!("invalid operator code");
                }
            }

            // keepalive + rotate loop
            loop {
                tokio::time::sleep(Duration::from_secs(warden.config.read().await.rotation.interval_seconds)).await;
                if let Some(s) = warden.status().await {
                    let up = (chrono::Utc::now() - s.connected_at).num_seconds();
                    info!("up {}s · {} bytes ↑↓", up, s.bytes_sent + s.bytes_received);
                } else {
                    info!("session lost — reconnecting");
                    if let Err(e) = warden.connect(&token).await {
                        error!("reconnect failed: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
        Err(e) => {
            error!("connection failed: {:?}", e);
            println!("❌ {:?}", e);
            std::process::exit(1);
        }
    }
}
