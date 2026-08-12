#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem, CustomMenuItem};
use warden_core::{config::*, models::*, error::*};
use warden_api::ApiClient;
use warden_proto::{ProtocolId, ProtocolCapabilities};
use warden_wireguard::WireGuardAdapter;
use warden_vless::VlessAdapter;
use warden_shadowsocks::ShadowsocksAdapter;
use warden_hysteria::HysteriaAdapter;
use warden_session::SessionManager;
use warden_policy::PolicyEngine;
use warden_transport::TransportManager;
use warden_crypto::KeyStore;
use warden_metrics::MetricsCollector;

mod commands;
mod state;
mod vpn;
mod opsec;
mod rotation;
mod config_manager;

use commands::*;
use state::AppState;
use vpn::VpnManager;
use opsec::OpsecManager;
use rotation::RotationManager;
use config_manager::ConfigManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Load configuration
    let config = WardenConfig::load().unwrap_or_default();
    
    // Initialize core components
    let key_store = Arc::new(SoftwareKeyStore::new(&config.database.path)?);
    let api_client = ApiClient::new(config.api.clone())?;
    let metrics = MetricsCollector::new(config.metrics.clone())?;
    
    // Initialize VPN manager with all protocol adapters
    let vpn_manager = VpnManager::new(
        config.protocols.clone(),
        key_store.clone(),
        api_client.clone(),
    ).await?;
    
    // Initialize OPsec manager
    let opsec_manager = OpsecManager::new(config.opsec.clone())?;
    
    // Initialize rotation manager
    let rotation_manager = RotationManager::new(
        config.rotation.clone(),
        vpn_manager.clone(),
        api_client.clone(),
    ).await?;
    
    // Initialize config manager
    let config_manager = ConfigManager::new(
        api_client.clone(),
        vpn_manager.clone(),
    ).await?;
    
    // Create app state
    let app_state = AppState {
        config: Arc::new(config),
        vpn_manager,
        opsec_manager,
        rotation_manager,
        config_manager,
        api_client,
        key_store,
        metrics,
    };
    
    // System tray
    let tray_menu = SystemTrayMenu::new()
        .add_item(CustomMenuItem::new("show".to_string(), "Show Warden"))
        .add_item(CustomMenuItem::new("connect".to_string(), "Connect"))
        .add_item(CustomMenuItem::new("disconnect".to_string(), "Disconnect"))
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(CustomMenuItem::new("settings".to_string(), "Settings"))
        .add_item(CustomMenuItem::new("quit".to_string(), "Quit"));
    
    let system_tray = SystemTray::new().with_menu(tray_menu);
    
    tauri::Builder::default()
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_log::Builder::new().build())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_global_shortcut::init())
        .plugin(tauri_plugin_tray_icon::init())
        .plugin(tauri_plugin_positioner::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => {
                match id.as_str() {
                    "show" => {
                        if let Some(window) = app.get_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "connect" => {
                        let state = app.state::<AppState>();
                        let _ = state.vpn_manager.connect_best().await;
                    }
                    "disconnect" => {
                        let state = app.state::<AppState>();
                        let _ = state.vpn_manager.disconnect().await;
                    }
                    "settings" => {
                        if let Some(window) = app.get_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                            let _ = window.emit("open-settings", ());
                        }
                    }
                    "quit" => {
                        std::process::exit(0);
                    }
                    _ => {}
                }
            }
            _ => {}
        })
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            // Connection commands
            connect,
            disconnect,
            get_connection_status,
            get_best_config,
            
            // Config commands
            fetch_configs,
            get_configs,
            add_custom_config,
            remove_custom_config,
            parse_subscription_url,
            import_subscription,
            
            // OPsec commands
            get_opsec_status,
            enable_opsec_feature,
            disable_opsec_feature,
            
            // Rotation commands
            get_rotation_status,
            set_rotation_interval,
            trigger_rotation,
            
            // Settings commands
            get_settings,
            update_settings,
            
            // Health/Monitoring
            get_health_status,
            get_metrics,
            test_config,
            
            // System
            check_updates,
            install_update,
        ])
        .setup(|app| {
            // Start background tasks
            let state = app.state::<AppState>();
            
            // Start config auto-refresh
            let config_manager = state.config_manager.clone();
            tauri::async_runtime::spawn(async move {
                config_manager.start_auto_refresh().await;
            });
            
            // Start rotation manager
            let rotation_manager = state.rotation_manager.clone();
            tauri::async_runtime::spawn(async move {
                rotation_manager.start().await;
            });
            
            // Start OPsec monitoring
            let opsec_manager = state.opsec_manager.clone();
            tauri::async_runtime::spawn(async move {
                opsec_manager.start_monitoring().await;
            });
            
            // Start metrics collection
            let metrics = state.metrics.clone();
            tauri::async_runtime::spawn(async move {
                metrics.start().await;
            });
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
    
    Ok(())
}