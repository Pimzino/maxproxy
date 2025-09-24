use anyhow::Result;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tokio::sync::Mutex;

mod oauth;
mod proxy;
mod storage;

use oauth::OAuthManager;
use proxy::{ProxyConfig, ProxyServer};
use storage::{TokenStatus, TokenStorage};

// Global application state
pub struct AppState {
    oauth_manager: Arc<Mutex<OAuthManager>>,
    proxy_server: Arc<ProxyServer>,
}

// Tauri command results
#[derive(Debug, Serialize, Deserialize)]
pub struct CommandResult<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> CommandResult<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// OAuth Commands
#[tauri::command]
async fn start_oauth_flow(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<String>, tauri::Error> {
    let mut oauth_manager = state.oauth_manager.lock().await;
    match oauth_manager.start_login_flow().await {
        Ok(auth_url) => Ok(CommandResult::success(auth_url)),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn exchange_oauth_code(
    code: String,
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    let oauth_manager = state.oauth_manager.lock().await;
    match oauth_manager.exchange_code(&code).await {
        Ok(token_response) => {
            match state.proxy_server.token_storage.save_tokens(&token_response) {
                Ok(_) => Ok(CommandResult::success(())),
                Err(e) => Ok(CommandResult::error(format!("Failed to save tokens: {}", e))),
            }
        }
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn refresh_token(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    let oauth_manager = state.oauth_manager.lock().await;

    match state.proxy_server.token_storage.get_refresh_token() {
        Ok(Some(refresh_token)) => {
            match oauth_manager.refresh_token(&refresh_token).await {
                Ok(token_response) => {
                    match state.proxy_server.token_storage.save_tokens(&token_response) {
                        Ok(_) => Ok(CommandResult::success(())),
                        Err(e) => Ok(CommandResult::error(format!("Failed to save refreshed tokens: {}", e))),
                    }
                }
                Err(e) => Ok(CommandResult::error(e.to_string())),
            }
        }
        Ok(None) => Ok(CommandResult::error("No refresh token available".to_string())),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

// Token Management Commands
#[tauri::command]
async fn get_token_status(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<TokenStatus>, tauri::Error> {
    match state.proxy_server.token_storage.get_status() {
        Ok(status) => Ok(CommandResult::success(status)),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn clear_tokens(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    match state.proxy_server.token_storage.clear_tokens() {
        Ok(_) => Ok(CommandResult::success(())),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

// Proxy Server Commands
#[tauri::command]
async fn start_proxy_server(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    match state.proxy_server.start().await {
        Ok(_) => Ok(CommandResult::success(())),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn stop_proxy_server(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    match state.proxy_server.stop().await {
        Ok(_) => Ok(CommandResult::success(())),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn get_proxy_status(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<bool>, tauri::Error> {
    Ok(CommandResult::success(state.proxy_server.is_running()))
}

#[tauri::command]
async fn get_proxy_config(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<ProxyConfig>, tauri::Error> {
    Ok(CommandResult::success(state.proxy_server.get_config()))
}

#[tauri::command]
async fn update_proxy_config(
    config: ProxyConfig,
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    match state.proxy_server.update_config(config) {
        Ok(_) => Ok(CommandResult::success(())),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

// Logging Commands
#[tauri::command]
async fn get_logs(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<Vec<String>>, tauri::Error> {
    Ok(CommandResult::success(state.proxy_server.get_logs()))
}

#[tauri::command]
async fn clear_logs(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    state.proxy_server.clear_logs();
    Ok(CommandResult::success(()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Initialize application state
    println!("[App] Initializing MaxProxy application...");
    let token_storage = match TokenStorage::new() {
        Ok(storage) => {
            println!("[App] ✓ Token storage initialized successfully");
            storage
        }
        Err(e) => {
            eprintln!("[App] ✗ Failed to initialize token storage: {}", e);
            std::process::exit(1);
        }
    };

    let oauth_manager = Arc::new(Mutex::new(OAuthManager::new()));
    let proxy_server = Arc::new(ProxyServer::new(token_storage, oauth_manager.clone()));

    let app_state = AppState {
        oauth_manager,
        proxy_server,
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            start_oauth_flow,
            exchange_oauth_code,
            refresh_token,
            get_token_status,
            clear_tokens,
            start_proxy_server,
            stop_proxy_server,
            get_proxy_status,
            get_proxy_config,
            update_proxy_config,
            get_logs,
            clear_logs
        ])
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                let webview_window = app.get_webview_window("main").unwrap();
                webview_window.open_devtools();

                // Disable WebView2 caching in development mode
                webview_window.eval(
                    r#"
                    console.log('🚫 Disabling WebView2 caching for development...');

                    // Disable service workers
                    if ('serviceWorker' in navigator) {
                        navigator.serviceWorker.getRegistrations().then(function(registrations) {
                            for(let registration of registrations) {
                                registration.unregister();
                                console.log('Unregistered service worker');
                            }
                        });
                    }

                    // Override fetch to disable caching (but not for IPC calls)
                    const originalFetch = window.fetch;
                    window.fetch = function(...args) {
                        // Don't modify Tauri IPC calls
                        if (args[0] && args[0].toString().includes('ipc.localhost')) {
                            return originalFetch.apply(this, args);
                        }

                        let options = args[1] || {};
                        options.cache = 'no-store';
                        options.headers = {
                            ...options.headers,
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                            'Pragma': 'no-cache'
                        };
                        args[1] = options;
                        return originalFetch.apply(this, args);
                    };

                    // Force refresh all stylesheets every 10 seconds in dev
                    const refreshCSS = () => {
                        const links = document.querySelectorAll('link[rel="stylesheet"]');
                        links.forEach(link => {
                            const href = link.href.split('?')[0];
                            link.href = href + '?t=' + Date.now();
                        });
                    };

                    // Initial CSS refresh after 2 seconds
                    setTimeout(refreshCSS, 2000);

                    // Periodic CSS refresh every 10 seconds
                    setInterval(refreshCSS, 10000);

                    console.log('✅ WebView2 cache bypassing enabled');
                    "#
                ).ok();

                // Add force reload capability (Ctrl+Shift+R for hard reload)
                webview_window.eval(
                    r#"
                    document.addEventListener('keydown', function(e) {
                        if (e.ctrlKey && e.shiftKey && e.key === 'R') {
                            console.log('🔄 Force reloading WebView...');
                            location.reload(true);
                            e.preventDefault();
                        }
                    });
                    console.log('🎯 Force reload with Ctrl+Shift+R enabled');
                    "#
                ).ok();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
