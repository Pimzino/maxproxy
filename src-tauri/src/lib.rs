use anyhow::Result;
use parking_lot::Mutex as SyncMutex;
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tauri::{
    menu::{CheckMenuItem, MenuBuilder, MenuItem},
    tray::{MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager, WindowEvent, Wry,
};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt as AutostartManagerExt};
use tokio::sync::Mutex;

mod oauth;
mod proxy;
mod storage;
mod cert;

use oauth::OAuthManager;
use proxy::{LogEntry, ProxyConfig, ProxyServer};
use storage::{TokenStatus, TokenStorage};

const TRAY_ID: &str = "maxproxy_tray";
const TRAY_TOGGLE_WINDOW_ID: &str = "tray_toggle_window";
const TRAY_START_PROXY_ID: &str = "tray_start_proxy";
const TRAY_STOP_PROXY_ID: &str = "tray_stop_proxy";
const TRAY_QUIT_ID: &str = "tray_quit";
const TRAY_PREF_START_MINIMIZED_ID: &str = "tray_pref_start_minimized";
const TRAY_PREF_AUTO_START_PROXY_ID: &str = "tray_pref_auto_start_proxy";
const TRAY_PREF_LAUNCH_ON_STARTUP_ID: &str = "tray_pref_launch_on_startup";

#[cfg(target_os = "windows")]
const LAUNCH_MENU_LABEL: &str = "Launch with Windows";
#[cfg(target_os = "macos")]
const LAUNCH_MENU_LABEL: &str = "Launch at Login";
#[cfg(target_os = "linux")]
const LAUNCH_MENU_LABEL: &str = "Launch on Startup";
#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
const LAUNCH_MENU_LABEL: &str = "Launch on Startup";

type Runtime = Wry;
type TrayMenuItem = MenuItem<Runtime>;
type TrayCheckItem = CheckMenuItem<Runtime>;

// Global application state
pub struct AppState {
    oauth_manager: Arc<Mutex<OAuthManager>>,
    proxy_server: Arc<ProxyServer>,
    init_status: Arc<Mutex<InitStatus>>,
    tray_menu_state: Arc<SyncMutex<Option<TrayMenuState>>>,
    allow_quit: Arc<AtomicBool>,
}

struct TrayMenuState {
    toggle_window_item: TrayMenuItem,
    start_proxy_item: TrayMenuItem,
    stop_proxy_item: TrayMenuItem,
    start_minimized_item: TrayCheckItem,
    auto_start_proxy_item: TrayCheckItem,
    launch_on_startup_item: TrayCheckItem,
}

impl TrayMenuState {
    fn new(
        toggle_window_item: TrayMenuItem,
        start_proxy_item: TrayMenuItem,
        stop_proxy_item: TrayMenuItem,
        start_minimized_item: TrayCheckItem,
        auto_start_proxy_item: TrayCheckItem,
        launch_on_startup_item: TrayCheckItem,
    ) -> Self {
        Self {
            toggle_window_item,
            start_proxy_item,
            stop_proxy_item,
            start_minimized_item,
            auto_start_proxy_item,
            launch_on_startup_item,
        }
    }

    fn set_proxy_running(&self, running: bool) {
        if let Err(e) = self.start_proxy_item.set_enabled(!running) {
            eprintln!("[Tray] Failed to update start item state: {}", e);
        }

        if let Err(e) = self.stop_proxy_item.set_enabled(running) {
            eprintln!("[Tray] Failed to update stop item state: {}", e);
        }
    }

    fn set_preferences(&self, config: &ProxyConfig) {
        if let Err(e) = self.start_minimized_item.set_checked(config.start_minimized) {
            eprintln!("[Tray] Failed to update start minimized toggle: {}", e);
        }
        if let Err(e) = self
            .auto_start_proxy_item
            .set_checked(config.auto_start_proxy)
        {
            eprintln!("[Tray] Failed to update auto start proxy toggle: {}", e);
        }
        if let Err(e) = self
            .launch_on_startup_item
            .set_checked(config.launch_on_startup)
        {
            eprintln!("[Tray] Failed to update launch on startup toggle: {}", e);
        }
    }

    fn set_window_visible(&self, visible: bool) {
        let label = if visible {
            "Hide MaxProxy"
        } else {
            "Show MaxProxy"
        };

        if let Err(e) = self.toggle_window_item.set_text(label) {
            eprintln!("[Tray] Failed to update window toggle label: {}", e);
        }
    }
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
    app: AppHandle<Runtime>,
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    match state.proxy_server.start().await {
        Ok(_) => {
            update_tray_proxy_state(&app, true);
            Ok(CommandResult::success(()))
        }
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn stop_proxy_server(
    app: AppHandle<Runtime>,
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    match state.proxy_server.stop().await {
        Ok(_) => {
            update_tray_proxy_state(&app, false);
            Ok(CommandResult::success(()))
        }
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
    app: AppHandle<Runtime>,
    config: ProxyConfig,
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<()>, tauri::Error> {
    let previous = state.proxy_server.get_config();

    if let Err(e) = state.proxy_server.update_config(config.clone()) {
        return Ok(CommandResult::error(e.to_string()));
    }

    apply_config_side_effects(&app, &state, &previous, &config);

    Ok(CommandResult::success(()))
}

#[tauri::command]
async fn trust_proxy_certificate(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<String>, tauri::Error> {
    match state.proxy_server.trust_certificate() {
        Ok(message) => Ok(CommandResult::success(message)),
        Err(e) => Ok(CommandResult::error(e.to_string())),
    }
}

#[tauri::command]
async fn get_accessible_endpoints(
    state: tauri::State<'_, AppState>,
) -> Result<CommandResult<Vec<String>>, tauri::Error> {
    Ok(CommandResult::success(
        state.proxy_server.accessible_endpoints(),
    ))
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

    let tray_menu_state = Arc::new(SyncMutex::new(None));
    let allow_quit = Arc::new(AtomicBool::new(false));

    let app_state = AppState {
        oauth_manager: oauth_manager.clone(),
        proxy_server: proxy_server.clone(),
        init_status: init_status.clone(),
        tray_menu_state: tray_menu_state.clone(),
        allow_quit: allow_quit.clone(),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, None))
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
            trust_proxy_certificate,
            get_accessible_endpoints,
            get_logs,
            clear_logs,
            get_init_status,
            get_system_info
        ])
        .setup(|app| {
            setup_system_tray(app)?;

            let app_handle = app.handle();

            if let Some(main_window) = app.get_webview_window("main") {
                let allow_quit_flag = app.state::<AppState>().allow_quit.clone();
                let app_handle_for_event = app_handle.clone();
                let window_clone = main_window.clone();

                main_window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        if !allow_quit_flag.load(Ordering::Relaxed) {
                            api.prevent_close();
                            if let Err(e) = window_clone.hide() {
                                eprintln!("[Tray] Failed to hide window: {}", e);
                            }
                            update_tray_window_state(&app_handle_for_event, false);
                        }
                    }
                });
            }

            // Apply persisted preference settings
            let config_snapshot = {
                let state = app.state::<AppState>();
                state.proxy_server.get_config()
            };

    {
        let state_ref = app.state::<AppState>();
        apply_config_side_effects(&app_handle, &state_ref, &ProxyConfig::default(), &config_snapshot);
    }

    // Perform token initialization asynchronously
    let app_handle_for_init = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let app_state = app_handle_for_init.state::<AppState>();
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

fn setup_system_tray(app: &tauri::App) -> tauri::Result<()> {
    let app_handle: AppHandle<Runtime> = app.handle().clone();
    let config_snapshot = {
        let state = app.state::<AppState>();
        state.proxy_server.get_config()
    };

    let toggle_item = TrayMenuItem::with_id(
        &app_handle,
        TRAY_TOGGLE_WINDOW_ID,
        "Hide MaxProxy",
        true,
        None::<&str>,
    )?;
    let start_item = TrayMenuItem::with_id(
        &app_handle,
        TRAY_START_PROXY_ID,
        "Start Proxy",
        true,
        None::<&str>,
    )?;
    let stop_item = TrayMenuItem::with_id(
        &app_handle,
        TRAY_STOP_PROXY_ID,
        "Stop Proxy",
        true,
        None::<&str>,
    )?;
    let start_minimized_item = TrayCheckItem::with_id(
        &app_handle,
        TRAY_PREF_START_MINIMIZED_ID,
        "Start Minimized",
        true,
        config_snapshot.start_minimized,
        None::<&str>,
    )?;
    let auto_start_proxy_item = TrayCheckItem::with_id(
        &app_handle,
        TRAY_PREF_AUTO_START_PROXY_ID,
        "Start Proxy on Launch",
        true,
        config_snapshot.auto_start_proxy,
        None::<&str>,
    )?;
    let launch_on_startup_item = TrayCheckItem::with_id(
        &app_handle,
        TRAY_PREF_LAUNCH_ON_STARTUP_ID,
        LAUNCH_MENU_LABEL,
        true,
        config_snapshot.launch_on_startup,
        None::<&str>,
    )?;
    let quit_item =
        TrayMenuItem::with_id(&app_handle, TRAY_QUIT_ID, "Quit", true, None::<&str>)?;

    let menu = MenuBuilder::new(&app_handle)
        .item(&toggle_item)
        .separator()
        .item(&start_item)
        .item(&stop_item)
        .separator()
        .item(&start_minimized_item)
        .item(&auto_start_proxy_item)
        .item(&launch_on_startup_item)
        .separator()
        .item(&quit_item)
        .build()?;

    {
        let app_state = app.state::<AppState>();
        let mut tray_menu_state = app_state.tray_menu_state.lock();
        *tray_menu_state = Some(TrayMenuState::new(
            toggle_item.clone(),
            start_item.clone(),
            stop_item.clone(),
            start_minimized_item.clone(),
            auto_start_proxy_item.clone(),
            launch_on_startup_item.clone(),
        ));
    }

    let mut tray_builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("MaxProxy Controls");

    if let Some(icon) = app.default_window_icon() {
        tray_builder = tray_builder.icon(icon.clone());
    }

    let tray_builder = tray_builder
        .on_menu_event(|app, event| {
            match event.id().as_ref() {
                TRAY_TOGGLE_WINDOW_ID => {
                    let app_handle = app.clone();
                    toggle_main_window(&app_handle);
                }
                TRAY_START_PROXY_ID => {
                    let app_handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let proxy_server = app_handle.state::<AppState>().proxy_server.clone();
                        match proxy_server.start().await {
                            Ok(_) => {
                                update_tray_proxy_state(&app_handle, true);
                            }
                            Err(e) => {
                                eprintln!("[Tray] Failed to start proxy: {}", e);
                            }
                        }
                    });
                }
                TRAY_STOP_PROXY_ID => {
                    let app_handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let proxy_server = app_handle.state::<AppState>().proxy_server.clone();
                        match proxy_server.stop().await {
                            Ok(_) => {
                                update_tray_proxy_state(&app_handle, false);
                            }
                            Err(e) => {
                                eprintln!("[Tray] Failed to stop proxy: {}", e);
                            }
                        }
                    });
                }
                TRAY_PREF_START_MINIMIZED_ID => {
                    let app_handle = app.clone();
                    let state = app.state::<AppState>();
                    let previous = state.proxy_server.get_config();
                    let mut updated = previous.clone();
                    updated.start_minimized = !previous.start_minimized;
                    if let Err(e) = state.proxy_server.update_config(updated.clone()) {
                        eprintln!("[Tray] Failed to update start minimized preference: {}", e);
                        update_tray_preferences(&app_handle, &previous);
                    } else {
                        apply_config_side_effects(&app_handle, &state, &previous, &updated);
                    }
                }
                TRAY_PREF_AUTO_START_PROXY_ID => {
                    let app_handle = app.clone();
                    let state = app.state::<AppState>();
                    let previous = state.proxy_server.get_config();
                    let mut updated = previous.clone();
                    updated.auto_start_proxy = !previous.auto_start_proxy;
                    if let Err(e) = state.proxy_server.update_config(updated.clone()) {
                        eprintln!("[Tray] Failed to update auto start proxy preference: {}", e);
                        update_tray_preferences(&app_handle, &previous);
                    } else {
                        apply_config_side_effects(&app_handle, &state, &previous, &updated);
                    }
                }
                TRAY_PREF_LAUNCH_ON_STARTUP_ID => {
                    let app_handle = app.clone();
                    let state = app.state::<AppState>();
                    let previous = state.proxy_server.get_config();
                    let mut updated = previous.clone();
                    updated.launch_on_startup = !previous.launch_on_startup;
                    if let Err(e) = state.proxy_server.update_config(updated.clone()) {
                        eprintln!("[Tray] Failed to update launch on startup preference: {}", e);
                        update_tray_preferences(&app_handle, &previous);
                    } else {
                        apply_config_side_effects(&app_handle, &state, &previous, &updated);
                    }
                }
                TRAY_QUIT_ID => {
                    let app_handle = app.clone();
                    let allow_quit_flag = app.state::<AppState>().allow_quit.clone();
                    let proxy_server = app.state::<AppState>().proxy_server.clone();
                    tauri::async_runtime::spawn(async move {
                        allow_quit_flag.store(true, Ordering::Relaxed);
                        if proxy_server.is_running() {
                            if let Err(e) = proxy_server.stop().await {
                                eprintln!("[Tray] Failed to stop proxy during quit: {}", e);
                            }
                        }
                        app_handle.exit(0);
                    });
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event: TrayIconEvent| {
            if let TrayIconEvent::Click {
                button,
                button_state,
                ..
            } = event
            {
                if matches!(button, tauri::tray::MouseButton::Left)
                    && button_state == MouseButtonState::Up
                {
                    let app_handle = tray.app_handle();
                    toggle_main_window(&app_handle);
                }
            }
        });

    tray_builder.build(&app_handle)?;

    let is_running = {
        let app_state = app.state::<AppState>();
        app_state.proxy_server.is_running()
    };

    update_tray_proxy_state(&app_handle, is_running);
    let window_visible = match app.get_webview_window("main") {
        Some(window) => window.is_visible().unwrap_or(true),
        None => true,
    };
    update_tray_window_state(&app_handle, window_visible);

    Ok(())
}

fn with_tray_state<F>(app: &AppHandle<Runtime>, f: F)
where
    F: FnOnce(&TrayMenuState),
{
    let app_state = app.state::<AppState>();
    let guard = app_state.tray_menu_state.lock();
    if let Some(tray_state) = guard.as_ref() {
        f(tray_state);
    }
}

fn update_tray_proxy_state(app: &AppHandle<Runtime>, running: bool) {
    with_tray_state(app, |tray_state| {
        tray_state.set_proxy_running(running);
    });
}

fn update_tray_preferences(app: &AppHandle<Runtime>, config: &ProxyConfig) {
    with_tray_state(app, |tray_state| {
        tray_state.set_preferences(config);
    });
}

fn update_tray_window_state(app: &AppHandle<Runtime>, visible: bool) {
    with_tray_state(app, |tray_state| {
        tray_state.set_window_visible(visible);
    });
}

fn apply_config_side_effects(
    app: &AppHandle<Runtime>,
    state: &tauri::State<'_, AppState>,
    previous: &ProxyConfig,
    config: &ProxyConfig,
) {
    if config.launch_on_startup != previous.launch_on_startup {
        let autostart_manager = app.autolaunch();
        let result = if config.launch_on_startup {
            autostart_manager.enable()
        } else {
            autostart_manager.disable()
        };
        if let Err(e) = result {
            eprintln!("[Autostart] Failed to update launch preference: {}", e);
        }
    }

    if config.start_minimized && !previous.start_minimized {
        if let Some(window) = app.get_webview_window("main") {
            if let Err(e) = window.hide() {
                eprintln!("[Tray] Failed to hide window for start minimized preference: {}", e);
            } else {
                update_tray_window_state(app, false);
            }
        }
    }

    if config.auto_start_proxy && !previous.auto_start_proxy {
        let proxy_server = state.proxy_server.clone();
        let app_handle = app.clone();
        tauri::async_runtime::spawn(async move {
            if !proxy_server.is_running() {
                match proxy_server.start().await {
                    Ok(_) => update_tray_proxy_state(&app_handle, true),
                    Err(e) => eprintln!("[Autostart] Failed to start proxy automatically: {}", e),
                }
            }
        });
    }

    update_tray_preferences(app, config);
}

fn toggle_main_window(app: &AppHandle<Runtime>) {
    if let Some(window) = app.get_webview_window("main") {
        match window.is_visible() {
            Ok(true) => {
                if let Err(e) = window.hide() {
                    eprintln!("[Tray] Failed to hide window: {}", e);
                } else {
                    update_tray_window_state(app, false);
                }
            }
            Ok(false) | Err(_) => {
                if let Err(e) = window.show() {
                    eprintln!("[Tray] Failed to show window: {}", e);
                } else {
                    let _ = window.unminimize();
                    let _ = window.set_focus();
                    update_tray_window_state(app, true);
                }
            }
        }
    }
}
