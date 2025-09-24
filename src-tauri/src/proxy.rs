use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use chrono;
use parking_lot::{Mutex, RwLock};
use tokio::sync::Mutex as TokioMutex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;

use crate::storage::TokenStorage;
use crate::oauth::OAuthManager;

// Anthropic API configuration (hardcoded - not user configurable)
const ANTHROPIC_VERSION: &str = "2023-06-01";
const ANTHROPIC_BETA: &str = "claude-code-20250219,oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14";
const API_BASE: &str = "https://api.anthropic.com";
const REQUEST_TIMEOUT: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub port: u16,
    pub bind_address: String,
    pub debug_mode: bool,
    pub openai_compatible: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8081,
            bind_address: "0.0.0.0".to_string(),
            debug_mode: false,
            openai_compatible: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinkingParameter {
    #[serde(rename = "type")]
    pub thinking_type: String,
    pub budget_tokens: u32,
}

impl Default for ThinkingParameter {
    fn default() -> Self {
        Self {
            thinking_type: "enabled".to_string(),
            budget_tokens: 16000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicMessageRequest {
    pub model: String,
    pub messages: Vec<Value>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingParameter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
}

#[derive(Debug)]
pub struct ProxyServer {
    config: Arc<RwLock<ProxyConfig>>,
    pub token_storage: Arc<TokenStorage>,
    oauth_manager: Arc<TokioMutex<OAuthManager>>,
    client: Client,
    running: Arc<AtomicBool>,
    server_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    logs: Arc<Mutex<Vec<String>>>,
}

impl ProxyServer {
    pub fn new(token_storage: TokenStorage, oauth_manager: Arc<TokioMutex<OAuthManager>>) -> Self {
        // Load saved configuration or use defaults
        let initial_config = token_storage.load_config()
            .unwrap_or(None)
            .unwrap_or_else(ProxyConfig::default);

        Self {
            config: Arc::new(RwLock::new(initial_config)),
            token_storage: Arc::new(token_storage),
            oauth_manager,
            client: Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT))
                .build()
                .expect("Failed to create HTTP client"),
            running: Arc::new(AtomicBool::new(false)),
            server_handle: Arc::new(Mutex::new(None)),
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn get_config(&self) -> ProxyConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, new_config: ProxyConfig) -> Result<()> {
        // Save configuration to file for persistence
        if let Err(e) = self.token_storage.save_config(&new_config) {
            // Log error but don't fail the operation
            self.log(format!("Warning: Failed to save configuration: {}", e));
        }

        let mut config = self.config.write();
        *config = new_config;
        Ok(())
    }

    pub fn get_logs(&self) -> Vec<String> {
        self.logs.lock().clone()
    }

    pub fn clear_logs(&self) {
        self.logs.lock().clear();
    }

    fn log(&self, message: String) {
        let mut logs = self.logs.lock();
        logs.push(format!("[{}] {}", chrono::Utc::now().format("%H:%M:%S"), message));

        // Keep only last 1000 log entries
        let len = logs.len();
        if len > 1000 {
            logs.drain(0..len - 1000);
        }
    }

    /// Get valid access token with automatic refresh if expired
    pub async fn get_valid_access_token(&self, request_id: &str) -> Result<Option<String>> {
        // First try to get current access token
        match self.token_storage.get_access_token() {
            Ok(Some(token)) => {
                // We have a valid token that's not expired
                return Ok(Some(token));
            }
            Ok(None) => {
                // Token is expired or doesn't exist, try to refresh
                self.log(format!("[{}] Access token expired, attempting automatic refresh...", request_id));
            }
            Err(e) => {
                self.log(format!("[{}] Error getting access token: {}", request_id, e));
                return Err(e);
            }
        }

        // Try to get refresh token
        let refresh_token = match self.token_storage.get_refresh_token() {
            Ok(Some(token)) => token,
            Ok(None) => {
                self.log(format!("[{}] No refresh token available", request_id));
                return Ok(None);
            }
            Err(e) => {
                self.log(format!("[{}] Error getting refresh token: {}", request_id, e));
                return Err(e);
            }
        };

        // Attempt to refresh tokens
        let oauth_manager = self.oauth_manager.lock().await;
        match oauth_manager.refresh_token(&refresh_token).await {
            Ok(token_response) => {
                self.log(format!("[{}] ✓ Successfully refreshed tokens", request_id));

                // Save the new tokens
                match self.token_storage.save_tokens(&token_response) {
                    Ok(_) => {
                        self.log(format!("[{}] ✓ Saved refreshed tokens", request_id));
                        Ok(Some(token_response.access_token))
                    }
                    Err(e) => {
                        self.log(format!("[{}] ✗ Failed to save refreshed tokens: {}", request_id, e));
                        Err(e)
                    }
                }
            }
            Err(e) => {
                self.log(format!("[{}] ✗ Failed to refresh token: {}", request_id, e));
                self.log(format!("[{}] Please re-authenticate using the OAuth flow", request_id));
                Ok(None)
            }
        }
    }

    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(anyhow!("Server is already running"));
        }

        let config = self.get_config();
        let addr = format!("{}:{}", config.bind_address, config.port);
        let socket_addr: SocketAddr = addr.parse()?;

        let listener = TcpListener::bind(&socket_addr).await?;
        self.log(format!("Proxy server starting on {}", addr));

        // Build the router
        let app = self.build_router();

        self.running.store(true, Ordering::Relaxed);

        let server_logs = self.logs.clone();
        let server_running = self.running.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                let mut logs = server_logs.lock();
                logs.push(format!("[{}] Server error: {}", chrono::Utc::now().format("%H:%M:%S"), e));
            }
            server_running.store(false, Ordering::Relaxed);
        });

        *self.server_handle.lock() = Some(handle);
        self.log("Proxy server started successfully".to_string());

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(anyhow!("Server is not running"));
        }

        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.server_handle.lock().take() {
            handle.abort();
            self.log("Proxy server stopped".to_string());
        }

        Ok(())
    }

    fn build_router(&self) -> Router {
        let state = ProxyState {
            token_storage: self.token_storage.clone(),
            oauth_manager: self.oauth_manager.clone(),
            client: self.client.clone(),
            logs: self.logs.clone(),
            config: self.config.clone(),
        };

        Router::new()
            .route("/v1/messages", post(handle_messages))
            .route("/v1/chat/completions", post(handle_openai_chat))
            .route("/health", get(handle_health))
            .route("/*path", any(handle_fallback))
            .layer(
                ServiceBuilder::new()
                    .layer(CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any))
            )
            .with_state(state)
    }
}

#[derive(Clone)]
struct ProxyState {
    pub token_storage: Arc<TokenStorage>,
    oauth_manager: Arc<TokioMutex<OAuthManager>>,
    client: Client,
    logs: Arc<Mutex<Vec<String>>>,
    config: Arc<RwLock<ProxyConfig>>,
}

impl ProxyState {
    fn log(&self, message: String) {
        let mut logs = self.logs.lock();
        logs.push(format!("[{}] {}", chrono::Utc::now().format("%H:%M:%S"), message));

        let len = logs.len();
        if len > 1000 {
            logs.drain(0..len - 1000);
        }
    }

    /// Get valid access token with automatic refresh if expired
    pub async fn get_valid_access_token(&self, request_id: &str) -> Result<Option<String>> {
        // First try to get current access token
        match self.token_storage.get_access_token() {
            Ok(Some(token)) => {
                // We have a valid token that's not expired
                return Ok(Some(token));
            }
            Ok(None) => {
                // Token is expired or doesn't exist, try to refresh
                self.log(format!("[{}] Access token expired, attempting automatic refresh...", request_id));
            }
            Err(e) => {
                self.log(format!("[{}] Error getting access token: {}", request_id, e));
                return Err(e);
            }
        }

        // Try to get refresh token
        let refresh_token = match self.token_storage.get_refresh_token() {
            Ok(Some(token)) => token,
            Ok(None) => {
                self.log(format!("[{}] No refresh token available", request_id));
                return Ok(None);
            }
            Err(e) => {
                self.log(format!("[{}] Error getting refresh token: {}", request_id, e));
                return Err(e);
            }
        };

        // Attempt to refresh tokens
        let oauth_manager = self.oauth_manager.lock().await;
        match oauth_manager.refresh_token(&refresh_token).await {
            Ok(token_response) => {
                self.log(format!("[{}] ✓ Successfully refreshed tokens", request_id));

                // Save the new tokens
                match self.token_storage.save_tokens(&token_response) {
                    Ok(_) => {
                        self.log(format!("[{}] ✓ Saved refreshed tokens", request_id));
                        Ok(Some(token_response.access_token))
                    }
                    Err(e) => {
                        self.log(format!("[{}] ✗ Failed to save refreshed tokens: {}", request_id, e));
                        Err(e)
                    }
                }
            }
            Err(e) => {
                self.log(format!("[{}] ✗ Failed to refresh token: {}", request_id, e));
                self.log(format!("[{}] Please re-authenticate using the OAuth flow", request_id));
                Ok(None)
            }
        }
    }
}

async fn handle_messages(
    axum::extract::State(state): axum::extract::State<ProxyState>,
    headers: HeaderMap,
    Json(mut request): Json<AnthropicMessageRequest>,
) -> Result<Response, StatusCode> {
    let request_id = Uuid::new_v4().to_string()[..8].to_string();

    state.log(format!("[{}] Incoming request to /v1/messages", request_id));
    state.log(format!("[{}] Model: {}, Stream: {}",
        request_id,
        request.model,
        request.stream.unwrap_or(false)
    ));

    // Get valid access token with automatic refresh
    let access_token = match state.get_valid_access_token(&request_id).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            state.log(format!("[{}] No valid access token available - authentication required", request_id));
            return Err(StatusCode::UNAUTHORIZED);
        },
        Err(e) => {
            state.log(format!("[{}] Token authentication error: {}", request_id, e));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Inject Claude Code system message to bypass authentication detection
    inject_claude_code_system_message(&mut request);

    // Sanitize the request
    sanitize_anthropic_request(&mut request);

    // Build the forwarded request with Claude Code headers
    let mut req_builder = state.client
        .post(&format!("{}/v1/messages?beta=true", API_BASE))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .header("host", "api.anthropic.com")
        .header("Accept", "application/json")
        .header("X-Stainless-Retry-Count", "0")
        .header("X-Stainless-Timeout", "600")
        .header("X-Stainless-Lang", "js")
        .header("X-Stainless-Package-Version", "0.60.0")
        .header("X-Stainless-OS", "Windows")
        .header("X-Stainless-Arch", "x64")
        .header("X-Stainless-Runtime", "node")
        .header("X-Stainless-Runtime-Version", "v22.19.0")
        .header("anthropic-dangerous-direct-browser-access", "true")
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header("x-app", "cli")
        .header("User-Agent", "claude-cli/1.0.113 (external, cli)")
        .header("anthropic-beta", ANTHROPIC_BETA)
        .header("x-stainless-helper-method", "stream")
        .header("accept-language", "*")
        .header("sec-fetch-mode", "cors");

    // Forward relevant headers
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(user_agent_str) = user_agent.to_str() {
            req_builder = req_builder.header("X-Forwarded-User-Agent", user_agent_str);
        }
    }

    let response = match req_builder.json(&request).send().await {
        Ok(resp) => resp,
        Err(e) => {
            state.log(format!("[{}] Request failed: {}", request_id, e));
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status = response.status();
    state.log(format!("[{}] Anthropic API responded with: {}", request_id, status));

    if request.stream.unwrap_or(false) {
        // Handle streaming response
        let stream = response.bytes_stream();
        let body = Body::from_stream(stream);

        Ok(Response::builder()
            .status(status.as_u16())
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive")
            .body(body)
            .unwrap())
    } else {
        // Handle non-streaming response
        let response_text = response.text().await.unwrap_or_default();

        Ok(Response::builder()
            .status(status.as_u16())
            .header("Content-Type", "application/json")
            .body(Body::from(response_text))
            .unwrap())
    }
}

async fn handle_openai_chat(
    axum::extract::State(state): axum::extract::State<ProxyState>,
    _headers: HeaderMap,
    Json(_request): Json<Value>,
) -> Result<Response, StatusCode> {
    let config = state.config.read();
    if !config.openai_compatible {
        return Err(StatusCode::NOT_FOUND);
    }

    let request_id = Uuid::new_v4().to_string()[..8].to_string();
    state.log(format!("[{}] OpenAI compatible request to /v1/chat/completions", request_id));

    // TODO: Transform OpenAI request to Anthropic format
    // This is a placeholder for the OpenAI compatibility layer

    Err(StatusCode::NOT_IMPLEMENTED)
}

async fn handle_health() -> impl IntoResponse {
    Json(json!({"status": "ok", "service": "MaxProxy"}))
}

async fn handle_fallback(uri: Uri, method: Method) -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": {
                "type": "not_found",
                "message": format!("Unknown endpoint: {} {}", method, uri.path())
            }
        }))
    )
}

fn inject_claude_code_system_message(request: &mut AnthropicMessageRequest) {
    // The exact spoof message from Claude Code - must be first system message
    let claude_code_spoof_element = json!({
        "type": "text",
        "text": "You are Claude Code, Anthropic's official CLI for Claude.",
        "cache_control": {"type": "ephemeral"}
    });

    // Claude Code uses array format for system messages
    if let Some(existing_system) = &mut request.system {
        // Prepend our spoof element to the existing system array
        existing_system.insert(0, claude_code_spoof_element);
    } else {
        // No existing system message - create array with just the spoof
        request.system = Some(vec![claude_code_spoof_element]);
    }
}

fn sanitize_anthropic_request(request: &mut AnthropicMessageRequest) {
    // Universal parameter validation - clean invalid values
    if let Some(top_p) = request.top_p {
        if !(0.0..=1.0).contains(&top_p) {
            request.top_p = None;
        }
    }

    if let Some(temperature) = request.temperature {
        if !(0.0..=2.0).contains(&temperature) {
            request.temperature = None;
        }
    }

    if let Some(top_k) = request.top_k {
        if top_k == 0 || top_k > 500 {
            request.top_k = None;
        }
    }
}