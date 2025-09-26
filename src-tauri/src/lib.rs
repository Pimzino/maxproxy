use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::Manager;
use tokio::sync::Mutex;

mod oauth;
mod proxy;
mod storage;

use oauth::OAuthManager;
use proxy::{LogEntry, ProxyConfig, ProxyServer};
use storage::{TokenStatus, TokenStorage};

// Global application state
pub struct AppState {
    oauth_manager: Arc<Mutex<OAuthManager>>,
    proxy_server: Arc<ProxyServer>,
    init_status: Arc<Mutex<InitStatus>>,
}

// App initialization status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitStatus {
    pub tokens_checked: bool,
    pub token_refresh_attempted: bool,
    pub token_refresh_successful: bool,
    pub initialization_complete: bool,
    pub error: Option<String>,
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

// System information for bug reports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub os: String,
    pub version: String,
    pub edition: Option<String>,
    pub arch: String,
}

#[tauri::command]
async fn get_system_info() -> CommandResult<SystemInfo> {
    let info = os_info::get();
    let os = info.os_type().to_string();
    let version = info.version().to_string();
    let edition = info.edition().map(|e| e.to_string());
    let arch = std::env::consts::ARCH.to_string();

    CommandResult::success(SystemInfo {
        os,
        version,
        edition,
        arch,
    })
}

// Automatic token renewal on startup
async fn initialize_tokens_with_auto_renewal(
    oauth_manager: Arc<Mutex<OAuthManager>>,
    token_storage: &TokenStorage,
) -> InitStatus {
    let mut status = InitStatus {
        tokens_checked: false,
        token_refresh_attempted: false,
        token_refresh_successful: false,
        initialization_complete: false,
        error: None,
    };

    println!("[TokenInit] Starting token initialization and auto-renewal check...");

    // Check if tokens exist and their status
    match token_storage.get_status() {
        Ok(token_status) => {
            status.tokens_checked = true;
            println!(
                "[TokenInit] Token status checked - has_tokens: {}, is_expired: {}",
                token_status.has_tokens, token_status.is_expired
            );

            // If we have tokens and they're expired, try to refresh them
            if token_status.has_tokens && token_status.is_expired {
                println!("[TokenInit] Tokens are expired, attempting automatic renewal...");
                status.token_refresh_attempted = true;

                match token_storage.get_refresh_token() {
                    Ok(Some(refresh_token)) => {
                        let oauth_manager = oauth_manager.lock().await;

                        // Use retry mechanism with 3 attempts
                        match oauth_manager
                            .refresh_token_with_retry(&refresh_token, 3)
                            .await
                        {
                            Ok(new_tokens) => {
                                // Save the new tokens
                                match token_storage.save_tokens(&new_tokens) {
                                    Ok(_) => {
                                        status.token_refresh_successful = true;
                                        println!("[TokenInit] ✓ Token renewal successful! Application ready.");
                                    }
                                    Err(e) => {
                                        let error_msg =
                                            format!("Failed to save refreshed tokens: {}", e);
                                        println!("[TokenInit] ✗ {}", error_msg);
                                        status.error = Some(error_msg);
                                    }
                                }
                            }
                            Err(e) => {
                                let error_msg = format!("All token refresh attempts failed: {}", e);
                                println!("[TokenInit] ✗ {}", error_msg);
                                status.error = Some(error_msg);
                            }
                        }
                    }
                    Ok(None) => {
                        let error_msg =
                            "No refresh token available for automatic renewal".to_string();
                        println!("[TokenInit] ✗ {}", error_msg);
                        status.error = Some(error_msg);
                    }
                    Err(e) => {
                        let error_msg = format!("Failed to retrieve refresh token: {}", e);
                        println!("[TokenInit] ✗ {}", error_msg);
                        status.error = Some(error_msg);
                    }
                }
            } else if token_status.has_tokens && !token_status.is_expired {
                println!("[TokenInit] ✓ Valid tokens found, no renewal needed.");
            } else {
                println!("[TokenInit] ℹ No tokens found, user will need to authenticate.");
            }
        }
        Err(e) => {
            let error_msg = format!("Failed to check token status: {}", e);
            println!("[TokenInit] ✗ {}", error_msg);
            status.error = Some(error_msg);
        }
    }

    status.initialization_complete = true;
    println!("[TokenInit] Token initialization complete.");
    status
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
            match state
                .proxy_server
                .token_storage
                .save_tokens(&token_response)
            {
                Ok(_) => {
                    // Schedule auto-refresh based on new expiry
                    state.proxy_server.schedule_token_refresh();
                    Ok(CommandResult::success(()))
                }
                Err(e) => Ok(CommandResult::error(format!(
                    "Failed to save tokens: {}",
                    e
                ))),
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
        Ok(Some(refresh_token)) => match oauth_manager.refresh_token(&refresh_token).await {
            Ok(token_response) => {
                match state
                    .proxy_server
                    .token_storage
                    .save_tokens(&token_response)
                {
                    Ok(_) => {
                        // Schedule auto-refresh based on new expiry
                        state.proxy_server.schedule_token_refresh();
                        Ok(CommandResult::success(()))
                    }
                    Err(e) => Ok(CommandResult::error(format!(
                        "Failed to save refreshed tokens: {}",
                        e
                    ))),
                }
            }
            Err(e) => Ok(CommandResult::error(e.to_string())),
        },
        Ok(None) => Ok(CommandResult::error(
            "No refresh token available".to_string(),
        )),
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
        Ok(_) => {
            // Cancel any scheduled token refresh
            state.proxy_server.cancel_token_refresh();
            Ok(CommandResult::success(()))
        },
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
) -> Result<CommandResult<Vec<LogEntry>>, tauri::Error> {
    Ok(CommandResult::success(state.proxy_server.get_logs()))
}

#[tauri::command]
async fn clear_logs(state: tauri::State<'_, AppState>) -> Result<CommandResult<()>, tauri::Error> {
    state.proxy_server.clear_logs();
    Ok(CommandResult::success(()))
}

// Initialization Commands
#[tauri::command]
async fn get_init_status(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<InitStatus>, tauri::Error> {
    let init_status = state.init_status.lock().await;
    Ok(CommandResult::success(init_status.clone()))
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

    // Initialize the app state with default init status
    let init_status = Arc::new(Mutex::new(InitStatus {
        tokens_checked: false,
        token_refresh_attempted: false,
        token_refresh_successful: false,
        initialization_complete: false,
        error: None,
    }));

    let app_state = AppState {
        oauth_manager: oauth_manager.clone(),
        proxy_server: proxy_server.clone(),
        init_status: init_status.clone(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
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
            clear_logs,
            get_init_status,
            get_system_info
        ])
        .setup(|app| {
            // Perform token initialization asynchronously
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let app_state = app_handle.state::<AppState>();
                let token_storage = &app_state.proxy_server.token_storage;
                let oauth_manager = app_state.oauth_manager.clone();
                let init_status_arc = app_state.init_status.clone();

                // Run token initialization with auto-renewal
                let status =
                    initialize_tokens_with_auto_renewal(oauth_manager, token_storage).await;

                // Update the shared init status
                {
                    let mut init_status = init_status_arc.lock().await;
                    *init_status = status;
                }

                // Schedule auto-refresh if tokens exist
                app_state.proxy_server.schedule_token_refresh();
            });

            #[cfg(debug_assertions)]
            {
                let webview_window = app.get_webview_window("main").unwrap();
                webview_window.open_devtools();

                // Disable WebView2 caching in development mode
                webview_window
                    .eval(
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
                    "#,
                    )
                    .ok();

                // Add force reload capability (Ctrl+Shift+R for hard reload)
                webview_window
                    .eval(
                        r#"
                    document.addEventListener('keydown', function(e) {
                        if (e.ctrlKey && e.shiftKey && e.key === 'R') {
                            console.log('🔄 Force reloading WebView...');
                            location.reload(true);
                            e.preventDefault();
                        }
                    });
                    console.log('🎯 Force reload with Ctrl+Shift+R enabled');
                    "#,
                    )
                    .ok();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
