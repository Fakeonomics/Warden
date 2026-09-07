use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::{error, info, warn};
use warden_core::{Updater, Warden, WardenConfig};

#[derive(Parser)]
#[command(name = "warden")]
#[command(about = "Warden VPN CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Connect {
        token: String,
    },
    Disconnect,
    Status,
    SelfTest,
    Update {
        #[arg(long, short)]
        check: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    print_ascii_logo();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warden=info,reqwest=warn".into()),
        )
        .init();

    let cli = Cli::parse();

    let mut config = WardenConfig::load()?;
    config.api.auth_token = std::env::var("WARDEN_TOKEN").ok();

    let warden = Warden::new(config).await?;

    match cli.command {
        Commands::Connect { token } => {
            info!("warden booting mode={:?}", warden.config.read().await.mode);
            match warden.connect(&token).await {
                Ok(conn) => {
                    info!(
                        "CONNECTED via {} -> {}:{} (sid:{})",
                        conn.protocol,
                        conn.host,
                        conn.port,
                        &conn.session_id[..8]
                    );
                    println!(
                        "Connected via {} to {}:{}",
                        conn.protocol, conn.host, conn.port
                    );

                    if let Ok(code) = std::env::var("WARDEN_OP_CODE") {
                        if warden.unlock_operator(&code).await {
                            println!("Operator mode unlocked");
                            let st = warden.opsec_status().await;
                            info!(
                                "opsec: fp={} hwid={} kill={}",
                                st.current_fingerprint,
                                &st.current_hwid[..8.min(st.current_hwid.len())],
                                st.kill_switch
                            );
                        } else {
                            warn!("invalid operator code");
                        }
                    }

                    loop {
                        tokio::time::sleep(Duration::from_secs(
                            warden.config.read().await.rotation.interval_seconds,
                        ))
                        .await;

                        // Unnoticeable rotation: rotate connections without disconnecting user fully
                        let all_active = warden.status_all().await;
                        if !all_active.is_empty() && warden.config.read().await.rotation.enabled {
                            info!(
                                "rotation triggered ({} active connections)",
                                all_active.len()
                            );
                            if let Err(e) = warden.rotate(&token).await {
                                warn!("rotation failed: {:?}", e);
                            } else {
                                info!("rotation completed successfully");
                            }
                        }

                        if let Some(s) = warden.status().await {
                            let up = (chrono::Utc::now() - s.connected_at).num_seconds();
                            info!(
                                "up {}s . {} bytes up/down ({} parallel tunnels)",
                                up,
                                s.bytes_sent + s.bytes_received,
                                warden.status_all().await.len()
                            );
                        } else {
                            info!("session lost - reconnecting");
                            if let Err(e) = warden.connect(&token).await {
                                error!("reconnect failed: {:?}", e);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("connection failed: {:?}", e);
                    println!("Failed: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Disconnect => {
            warden.disconnect().await?;
            println!("Disconnected");
        }
        Commands::Status => match warden.status().await {
            Some(s) => println!(
                "{} via {}:{} (sid:{})",
                s.protocol,
                s.host,
                s.port,
                &s.session_id[..8]
            ),
            None => println!("Not connected"),
        },
        Commands::SelfTest => {
            let report = warden_core::run_self_test().await?;
            println!(
                "ternary={} decision={:?} opsec_persist={} tunnel_proof={:?}",
                report.ternary_ok,
                report.decision_ranking,
                report.opsec_persist,
                report.tunnel_proof
            );
            if report.service_ok {
                println!("SERVICE OK");
            } else {
                println!("self-test FAILED");
                std::process::exit(1);
            }
        }
        Commands::Update { check } => {
            let ua = warden.config.read().await.api.user_agent.clone();
            let updater = Updater::with_default_client(ua, "Fakeonomics/Warden".to_string())?;

            match updater.check().await {
                Ok(Some(info)) => {
                    let remote_v = info.version().ok();
                    let local_v = warden_core::updater::local_version();
                    if let Some(rv) = &remote_v {
                        let avail = warden_core::updater::Version::parse(local_v)
                            .map(|l| l.compare(rv).is_lt())
                            .unwrap_or(false);
                        if check {
                            if avail {
                                println!(
                                    "update available: {} -> {}.{}.{}",
                                    local_v, rv.major, rv.minor, rv.patch
                                );
                            } else {
                                println!("up to date (v{})", local_v);
                            }
                        } else if avail {
                            let target = warden_core::updater::current_target();
                            if let Some(asset) = info.asset_for(&target) {
                                println!("downloading {} for {}", asset.name, target);
                                let bytes = updater.download_asset(asset).await?;
                                println!("installing ({} bytes)", bytes.len());
                                updater.install(&bytes).await?;
                                println!("installed v{}.{}.{}", rv.major, rv.minor, rv.patch);
                            } else {
                                println!("no asset for target {}", target);
                            }
                        } else {
                            println!("up to date (v{})", local_v);
                        }
                    } else if check {
                        println!("no release info");
                    } else {
                        println!("up to date (v{})", local_v);
                    }
                }
                Ok(None) => {
                    println!("no release available (rate-limited or none published)");
                }
                Err(e) => {
                    eprintln!("update check failed: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn print_ascii_logo() {
    let logo = r#"░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░"#;
    println!("{}", logo);
}
