use litcrypt2::lc;
use tauri::Manager;
use tracing_subscriber::EnvFilter;

lc!();

mod lib;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "warden=info".into()))
        .init();

    tauri::Builder::default()
        .set_window_class("warden")
        .manage(lib::AppState::new())
        .invoke_handler(tauri::generate_handler![
            lib::connect,
            lib::disconnect,
            lib::get_status,
            lib::fetch_configs,
            lib::get_opsec_status,
            lib::unlock_operator,
            lib::lock,
            lib::toggle_opsec_feature,
            lib::rotate_now,
        ])
        .setup(|app| {
            if let Some(win) = app.get_webview_window(lc!("main")) {
                win.set_title(lc!("Warden VPN")).ok();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error running warden app");
}
