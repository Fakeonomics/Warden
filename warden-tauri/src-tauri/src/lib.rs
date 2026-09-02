use parking_lot::RwLock;
use std::sync::Arc;
use warden_core::{Mode, Warden, WardenConfig};

pub struct AppState {
    pub warden: RwLock<Option<Arc<Warden>>>,
    pub config: RwLock<WardenConfig>,
    pub token: RwLock<String>,
}

impl AppState {
    pub fn new() -> Self {
        let mut config = WardenConfig::load().unwrap_or_default();
        config.api.auth_token = std::env::var("WARDEN_TOKEN").ok();
        let token = config.api.auth_token.clone().unwrap_or_default();
        Self {
            warden: RwLock::new(None),
            config: RwLock::new(config),
            token: RwLock::new(token),
        }
    }

    pub async fn ensure(&self) -> Result<Arc<Warden>, String> {
        {
            let g = self.warden.read();
            if let Some(w) = g.as_ref() {
                return Ok(w.clone());
            }
        }
        let mut g = self.warden.write();
        if let Some(w) = g.as_ref() {
            return Ok(w.clone());
        }
        let cfg = self.config.read().clone();
        let w = Arc::new(Warden::new(cfg).await.map_err(|e| format!("{e:?}"))?);
        *g = Some(w.clone());
        Ok(w)
    }

    fn token(&self) -> String {
        let t = self.token.read().clone();
        if t.is_empty() {
            "test".into()
        } else {
            t
        }
    }
}

#[tauri::command]
pub async fn connect(
    state: tauri::State<'_, AppState>,
) -> Result<warden_core::ActiveConnection, String> {
    let w = state.ensure().await?;
    w.connect(&state.token())
        .await
        .map_err(|e| format!("{e:?}"))
}

#[tauri::command]
pub async fn disconnect(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let w = state.ensure().await?;
    w.disconnect().await.map_err(|e| format!("{e:?}"))
}

#[tauri::command]
pub async fn get_status(
    state: tauri::State<'_, AppState>,
) -> Result<Option<warden_core::ActiveConnection>, String> {
    let w = state.ensure().await?;
    Ok(w.status().await)
}

#[tauri::command]
pub async fn fetch_configs(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<warden_core::api::ServerConfig>, String> {
    let w = state.ensure().await?;
    w.api
        .fetch_subscription(&state.token())
        .await
        .map_err(|e| format!("{e:?}"))
}

#[tauri::command]
pub async fn get_opsec_status(
    state: tauri::State<'_, AppState>,
) -> Result<warden_core::opsec::OpsecStatus, String> {
    let w = state.ensure().await?;
    Ok(w.opsec_status().await)
}

#[tauri::command]
pub async fn unlock_operator(
    code: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let w = state.ensure().await?;
    Ok(w.unlock_operator(&code).await)
}

#[tauri::command]
pub async fn lock(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let w = state.ensure().await?;
    w.lock().await;
    Ok(())
}

#[tauri::command]
pub async fn toggle_opsec_feature(
    field: String,
    value: bool,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    let w = state.ensure().await?;
    let mut opsec = w.opsec.write().await;
    Ok(opsec.toggle(&field, value))
}

#[tauri::command]
pub async fn rotate_now(
    state: tauri::State<'_, AppState>,
) -> Result<warden_core::ActiveConnection, String> {
    let w = state.ensure().await?;
    w.disconnect().await.map_err(|e| format!("{e:?}"))?;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    w.connect(&state.token())
        .await
        .map_err(|e| format!("{e:?}"))
}

#[tauri::command]
pub async fn rotate(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<warden_core::ActiveConnection>, String> {
    let w = state.ensure().await?;
    w.rotate(&state.token()).await.map_err(|e| format!("{e:?}"))
}

#[tauri::command]
pub async fn run_self_test() -> Result<warden_core::SelfTestReport, String> {
    warden_core::run_self_test()
        .await
        .map_err(|e| format!("{e:?}"))
}

#[tauri::command]
pub async fn get_mode(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let w = state.ensure().await?;
    let cfg = w.config.read().await.clone();
    Ok(match cfg.mode {
        warden_core::Mode::Civilian => "Civilian".into(),
        warden_core::Mode::Operator => "Operator".into(),
    })
}
