use tauri::State;
use warden_core::{models::*, error::*};
use tracing::{info, warn};

use crate::state::AppState;
use crate::vpn::ConnectionResult;

#[tauri::command]
pub async fn connect(state: State<'_, AppState>) -> ResultConnectionResult, String> {
    info!("Tauri connect command invoked");
    
    let vpn = state.vpn_manager.clone();
    let result = vpn.connect_best().await.map_err(|e| format!("{:?}", e))?;
    
    info!("Connected: protocol={:?}, server={}", result.protocol, result.server);
    Ok(result)
}

#[tauri::command]
pub async fn disconnect(state: State<'_, AppState>) -> Result<(), String> {
    info!("Tauri disconnect command invoked");
    
    let vpn = state.vpn_manager.clone();
    vpn.disconnect().await.map_err(|e| format!("{:?}", e))?;
    
    info!("Disconnected");
    Ok(())
}

#[tauri::command]
pub async fn get_connection_status(state: State<'_, AppState>) -> ResultConnectionStatus, String> {
    let vpn = state.vpn_manager.clone();
    Ok(vpn.get_status().await)
}

#[tauri::command]
pub async fn fetch_configs(state: State<'_, AppState>) -> Result<VecServerConfig>, String> {
    info!("Fetching configs from VPN-Service");
    
    let config_manager = state.config_manager.clone();
    config_manager.refresh_configs().await.map_err(|e| format!("{:?}", e))?;
    
    config_manager.get_configs().await.ok_or("No configs found".to_string())
}

#[tauri::command]
pub async fn add_custom_config(
    config_line: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    info!("Adding custom config: {}", name);
    
    let config_manager = state.config_manager.clone();
    config_manager.add_custom_config(&config_line, &name).await
        .map_err(|e| format!("{:?}", e))
}

#[tauri::command]
pub async fn get_opsec_status(state: State<'_, AppState>) -> Resultserde_json::Value, String> {
    let opsec = state.opsec_manager.clone();
    let status = opsec.get_status().await;
    Ok(serde_json::json!({
        "enabled": true,
        "fingerprint_rotation": status.fingerprint_enabled,
        "traffic_shaping": true,
        "hwid_spoof": status.hwid_enabled,
        "kill_switch": status.kill_switch,
        "dns_leak_protection": status.dns_protection,
        "ipv6_leak_protection": status.ipv6_protection,
        "padding": status.padding_enabled,
    }))
}

#[tauri::command]
pub async fn get_settings(state: State<'_, AppState>) -> Resultserde_json::Value, String> {
    Ok(serde_json::json!({
        "protocol_preference": state.config.read().await.protocols.preferred,
        "rotation_interval": state.config.read().await.rotation.interval_seconds,
        "opsec_enabled": state.config.read().await.opsec.enabled,
        "auto_connect": false,
    }))
}

#[tauri::command]
pub async fn parse_subscription_url(
    url: String,
    state: State<'_, AppState>,
) -> Resultserde_json::Value, String> {
    info!("Parsing subscription URL: {}", url);
    
    let api_client = state.api_client.clone();
    let result = api_client.parse_subscription(&url).await
        .map_err(|e| format!("{:?}", e))?;
    
    Ok(serde_json::json!({
        "success": true,
        "configs_found": result.len(),
        "protocols": result.iter().map(|c| c.protocol.clone()).collect::<Vec<String>>(),
    }))
}