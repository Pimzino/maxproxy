use anyhow::{anyhow, Result};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use chrono;
use futures_util::StreamExt;
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

// OpenAI API Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIMessage {
    pub role: String,
    pub content: Value, // Can be string or array of content parts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl OpenAIMessage {
    /// Extract text content from either string or array format
    pub fn get_text_content(&self) -> String {
        match &self.content {
            Value::String(text) => text.clone(),
            Value::Array(parts) => {
                let mut text_parts = Vec::new();
                for part in parts {
                    match part {
                        Value::String(text) => {
                            text_parts.push(text.clone());
                        },
                        Value::Object(obj) => {
                            // Handle objects with text field
                            if let Some(Value::String(text)) = obj.get("text") {
                                text_parts.push(text.clone());
                            }
                            // Also check for type="text" pattern
                            else if let (Some(Value::String(part_type)), Some(Value::String(text))) =
                                (obj.get("type"), obj.get("text")) {
                                if part_type == "text" {
                                    text_parts.push(text.clone());
                                }
                            }
                        },
                        _ => {} // Skip other types
                    }
                }
                text_parts.join(" ")
            },
            Value::Object(obj) => {
                // Handle single object with text field
                if let Some(Value::String(text)) = obj.get("text") {
                    text.clone()
                } else {
                    String::new()
                }
            },
            _ => String::new(), // Fallback for other types
        }
    }

    /// Extract content in Anthropic format (array of content objects)
    pub fn get_anthropic_content(&self) -> Value {
        match &self.content {
            Value::String(text) => {
                // Simple string -> single text object
                json!([{
                    "type": "text",
                    "text": text
                }])
            },
            Value::Array(parts) => {
                let mut anthropic_parts = Vec::new();
                for part in parts {
                    match part {
                        Value::String(text) => {
                            anthropic_parts.push(json!({
                                "type": "text",
                                "text": text
                            }));
                        },
                        Value::Object(obj) => {
                            // Preserve the object structure, ensuring it has type and text
                            let mut anthropic_obj = json!({
                                "type": "text"
                            });

                            // Copy all fields from the original object
                            if let Value::Object(anthropic_map) = &mut anthropic_obj {
                                for (key, value) in obj {
                                    anthropic_map.insert(key.clone(), value.clone());
                                }
                                // Ensure type is set to "text" if not already present
                                if !anthropic_map.contains_key("type") {
                                    anthropic_map.insert("type".to_string(), json!("text"));
                                }
                            }
                            anthropic_parts.push(anthropic_obj);
                        },
                        _ => {} // Skip other types
                    }
                }
                Value::Array(anthropic_parts)
            },
            Value::Object(obj) => {
                // Single object -> wrap in array
                let mut anthropic_obj = json!({
                    "type": "text"
                });

                if let Value::Object(anthropic_map) = &mut anthropic_obj {
                    for (key, value) in obj {
                        anthropic_map.insert(key.clone(), value.clone());
                    }
                    if !anthropic_map.contains_key("type") {
                        anthropic_map.insert("type".to_string(), json!("text"));
                    }
                }
                json!([anthropic_obj])
            },
            _ => {
                // Fallback -> empty text
                json!([{
                    "type": "text",
                    "text": ""
                }])
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIFunction {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpenAIFunctionCall {
    Auto(String), // "auto" or "none"
    Named { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAITool {
    #[serde(rename = "type")]
    pub tool_type: String, // "function"
    pub function: OpenAIFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIRequest {
    pub model: String,
    pub messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<OpenAIFunction>>, // Legacy functions parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_call: Option<OpenAIFunctionCall>, // Legacy function_call parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<OpenAITool>>, // New tools parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>, // Tool choice parameter
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIChoice {
    pub index: u32,
    pub message: OpenAIMessage,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIChoiceDelta {
    pub index: u32,
    pub delta: OpenAIDelta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChoice>,
    pub usage: OpenAIUsage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIStreamResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<OpenAIChoiceDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIModel {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub owned_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIModelsResponse {
    pub object: String,
    pub data: Vec<OpenAIModel>,
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
            .route("/v1/chat/completions", post(handle_openai_chat_impl))
            .route("/v1/models", get(handle_models))
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

    fn debug_log(&self, message: String) {
        let config = self.config.read();
        if config.debug_mode {
            drop(config); // Release the lock before calling log
            self.log(message);
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

async fn handle_models(
    axum::extract::State(state): axum::extract::State<ProxyState>,
) -> Result<Json<OpenAIModelsResponse>, StatusCode> {
    let config = state.config.read();
    if !config.openai_compatible {
        return Err(StatusCode::NOT_FOUND);
    }

    let models = vec![
        // Standard Anthropic models
        OpenAIModel {
            id: "claude-opus-4-1-20250805".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-opus-4-20250514".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-sonnet-4-20250514".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-3-7-sonnet-20250219".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-3-5-haiku-20241022".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-3-haiku-20240307".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },

        // Thinking variants for Claude Opus 4.1
        OpenAIModel {
            id: "claude-opus-4-1-20250805-thinking-low".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-opus-4-1-20250805-thinking-medium".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-opus-4-1-20250805-thinking-high".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },

        // Thinking variants for Claude Opus 4
        OpenAIModel {
            id: "claude-opus-4-20250514-thinking-low".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-opus-4-20250514-thinking-medium".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-opus-4-20250514-thinking-high".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },

        // Thinking variants for Claude Sonnet 4
        OpenAIModel {
            id: "claude-sonnet-4-20250514-thinking-low".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-sonnet-4-20250514-thinking-medium".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-sonnet-4-20250514-thinking-high".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },

        // Thinking variants for Claude Sonnet 3.7
        OpenAIModel {
            id: "claude-3-7-sonnet-20250219-thinking-low".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-3-7-sonnet-20250219-thinking-medium".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
        OpenAIModel {
            id: "claude-3-7-sonnet-20250219-thinking-high".to_string(),
            object: "model".to_string(),
            created: 1687882411,
            owned_by: "anthropic".to_string(),
        },
    ];

    Ok(Json(OpenAIModelsResponse {
        object: "list".to_string(),
        data: models,
    }))
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

// Transform Anthropic streaming chunk to OpenAI format
fn transform_anthropic_streaming_chunk(
    chunk: &[u8],
    request_id: &str,
    original_model: &str,
    created: u64
) -> Result<Vec<String>, anyhow::Error> {
    let chunk_str = std::str::from_utf8(chunk)?;
    let mut openai_chunks = Vec::new();

    // Parse SSE format - split by double newlines for events
    for event_block in chunk_str.split("\n\n") {
        if event_block.trim().is_empty() {
            continue;
        }

        let mut event_type = None;
        let mut data_content = None;

        // Parse SSE fields
        for line in event_block.lines() {
            if let Some(stripped) = line.strip_prefix("event: ") {
                event_type = Some(stripped);
            } else if let Some(stripped) = line.strip_prefix("data: ") {
                data_content = Some(stripped);
            }
        }

        if let Some(data) = data_content {
            match event_type {
                Some("message_start") => {
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        let openai_chunk = OpenAIStreamResponse {
                            id: format!("chatcmpl-{}", request_id),
                            object: "chat.completion.chunk".to_string(),
                            created,
                            model: original_model.to_string(),
                            choices: vec![OpenAIChoiceDelta {
                                index: 0,
                                delta: OpenAIDelta {
                                    role: Some("assistant".to_string()),
                                    content: Some("".to_string()),
                                },
                                finish_reason: None,
                            }],
                        };

                        let formatted = format!("data: {}\n\n", serde_json::to_string(&openai_chunk)?);
                        openai_chunks.push(formatted);
                    }
                },
                Some("content_block_delta") => {
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        if let Some(delta) = data_json.get("delta") {
                            if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                                let openai_chunk = OpenAIStreamResponse {
                                    id: format!("chatcmpl-{}", request_id),
                                    object: "chat.completion.chunk".to_string(),
                                    created,
                                    model: original_model.to_string(),
                                    choices: vec![OpenAIChoiceDelta {
                                        index: 0,
                                        delta: OpenAIDelta {
                                            role: None,
                                            content: Some(text.to_string()),
                                        },
                                        finish_reason: None,
                                    }],
                                };

                                let formatted = format!("data: {}\n\n", serde_json::to_string(&openai_chunk)?);
                                openai_chunks.push(formatted);
                            }
                        }
                    }
                },
                Some("message_delta") => {
                    // Handle stop reason in message_delta
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        if let Some(stop_reason) = data_json.get("delta").and_then(|d| d.get("stop_reason")).and_then(|s| s.as_str()) {
                            let finish_reason = match stop_reason {
                                "end_turn" => "stop",
                                "max_tokens" => "length",
                                "stop_sequence" => "stop",
                                "tool_use" => "tool_calls",
                                _ => "stop",
                            };

                            let openai_chunk = OpenAIStreamResponse {
                                id: format!("chatcmpl-{}", request_id),
                                object: "chat.completion.chunk".to_string(),
                                created,
                                model: original_model.to_string(),
                                choices: vec![OpenAIChoiceDelta {
                                    index: 0,
                                    delta: OpenAIDelta {
                                        role: None,
                                        content: None,
                                    },
                                    finish_reason: Some(finish_reason.to_string()),
                                }],
                            };

                            let formatted = format!("data: {}\n\n", serde_json::to_string(&openai_chunk)?);
                            openai_chunks.push(formatted);
                        }
                    }
                },
                Some("message_stop") => {
                    // Final chunk
                    openai_chunks.push("data: [DONE]\n\n".to_string());
                },
                _ => {
                    // Skip unknown events or forward as-is for debugging
                }
            }
        }
    }

    Ok(openai_chunks)
}

async fn handle_openai_chat_impl(
    axum::extract::State(state): axum::extract::State<ProxyState>,
    headers: HeaderMap,
    Json(openai_request): Json<OpenAIRequest>,
) -> Result<Response, StatusCode> {
    let openai_compatible = {
        let config = state.config.read();
        config.openai_compatible
    };

    if !openai_compatible {
        return Err(StatusCode::NOT_FOUND);
    }

    let request_id = Uuid::new_v4().to_string()[..8].to_string();
    state.log(format!("[{}] OpenAI compatible request to /v1/chat/completions", request_id));
    state.log(format!("[{}] Model: {}, Stream: {}",
        request_id,
        openai_request.model,
        openai_request.stream.unwrap_or(false)
    ));

    // Debug logging for request body
    match serde_json::to_string_pretty(&openai_request) {
        Ok(request_json) => {
            state.debug_log(format!("[{}] [DEBUG] OpenAI request body:\n{}", request_id, request_json));
        },
        Err(e) => {
            state.debug_log(format!("[{}] [DEBUG] Failed to serialize request body: {}", request_id, e));
        }
    }

    // Transform OpenAI request to Anthropic format
    let mut anthropic_request = transform_openai_to_anthropic(&openai_request);

    // Get access token
    let access_token = match state.get_valid_access_token(&request_id).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            state.log(format!("[{}] No valid access token - authentication required", request_id));
            return Err(StatusCode::UNAUTHORIZED);
        },
        Err(e) => {
            state.log(format!("[{}] Token error: {}", request_id, e));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Inject Claude Code system message and sanitize
    inject_claude_code_system_message(&mut anthropic_request);
    sanitize_anthropic_request(&mut anthropic_request);

    // Debug logging for transformed Anthropic request
    match serde_json::to_string_pretty(&anthropic_request) {
        Ok(request_json) => {
            state.debug_log(format!("[{}] [DEBUG] Transformed Anthropic request body:\n{}", request_id, request_json));
        },
        Err(e) => {
            state.debug_log(format!("[{}] [DEBUG] Failed to serialize Anthropic request body: {}", request_id, e));
        }
    }

    // Make request to Anthropic API
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

    // Forward user-agent if present
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(user_agent_str) = user_agent.to_str() {
            req_builder = req_builder.header("X-Forwarded-User-Agent", user_agent_str);
        }
    }

    let response = match req_builder.json(&anthropic_request).send().await {
        Ok(resp) => resp,
        Err(e) => {
            state.log(format!("[{}] Request failed: {}", request_id, e));
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status = response.status();
    state.log(format!("[{}] Anthropic API response: {}", request_id, status));

    // Capture important headers before consuming the response
    let mut response_headers = Vec::new();
    for (name, value) in response.headers().iter() {
        let header_name = name.as_str();
        if header_name.starts_with("x-anthropic-ratelimit-") ||
           header_name.starts_with("anthropic-ratelimit-") ||
           header_name == "x-request-id" ||
           header_name == "anthropic-request-id" {
            if let Ok(value_str) = value.to_str() {
                response_headers.push((header_name.to_string(), value_str.to_string()));
            }
        }
    }

    if !status.is_success() {
        // Handle error response - transform to OpenAI format
        let error_text = response.text().await.unwrap_or_default();
        state.log(format!("[{}] Anthropic API error ({}): {}", request_id, status, &error_text));

        // Debug logging for raw Anthropic error response
        state.debug_log(format!("[{}] [DEBUG] Raw Anthropic error response:\n{}", request_id, error_text));

        // Try to parse and transform the error to OpenAI format
        let openai_error = match serde_json::from_str::<Value>(&error_text) {
            Ok(anthropic_error) => {
                // Check if it's an Anthropic error format
                if anthropic_error.get("type").and_then(|t| t.as_str()) == Some("error") {
                    state.debug_log(format!("[{}] [DEBUG] Transforming Anthropic error to OpenAI format", request_id));
                    transform_anthropic_error_to_openai(&anthropic_error)
                } else {
                    // Not standard Anthropic error format, create generic OpenAI error
                    json!({
                        "error": {
                            "message": "An error occurred",
                            "type": "api_error",
                            "param": null,
                            "code": null
                        }
                    })
                }
            },
            Err(_) => {
                // If we can't parse the error, create a generic OpenAI error
                json!({
                    "error": {
                        "message": "An error occurred while processing the request",
                        "type": "api_error",
                        "param": null,
                        "code": null
                    }
                })
            }
        };

        // Debug logging for transformed OpenAI error
        match serde_json::to_string_pretty(&openai_error) {
            Ok(error_json) => {
                state.debug_log(format!("[{}] [DEBUG] Transformed OpenAI error:\n{}", request_id, error_json));
            },
            Err(e) => {
                state.debug_log(format!("[{}] [DEBUG] Failed to serialize OpenAI error: {}", request_id, e));
            }
        }

        let mut response_builder = Response::builder()
            .status(status.as_u16())
            .header("Content-Type", "application/json");

        // Add captured headers
        for (name, value) in response_headers {
            response_builder = response_builder.header(&name, &value);
        }

        return Ok(response_builder
            .body(Body::from(serde_json::to_string(&openai_error).unwrap_or_else(|_| error_text)))
            .unwrap());
    }

    if openai_request.stream.unwrap_or(false) {
        // Transform streaming response from Anthropic to OpenAI format
        state.log(format!("[{}] Streaming response with OpenAI transformation", request_id));
        state.debug_log(format!("[{}] [DEBUG] Starting stream transformation", request_id));

        let created = chrono::Utc::now().timestamp() as u64;
        let original_model = openai_request.model.clone();
        let request_id_clone = request_id.to_string();
        let state_clone = state.clone();

        // Create a stream that transforms Anthropic chunks to OpenAI format
        let stream = response.bytes_stream().map(move |chunk_result| {
            match chunk_result {
                Ok(chunk) => {
                    state_clone.debug_log(format!("[{}] [DEBUG] Processing chunk: {} bytes", request_id_clone, chunk.len()));

                    match transform_anthropic_streaming_chunk(&chunk, &request_id_clone, &original_model, created) {
                        Ok(openai_chunks) => {
                            state_clone.debug_log(format!("[{}] [DEBUG] Transformed to {} OpenAI chunks", request_id_clone, openai_chunks.len()));
                            let combined = openai_chunks.join("");
                            Ok(bytes::Bytes::from(combined))
                        }
                        Err(e) => {
                            state_clone.log(format!("[{}] Stream transformation error: {}", request_id_clone, e));
                            // Forward original chunk on error
                            Ok(chunk)
                        }
                    }
                }
                Err(e) => {
                    state_clone.log(format!("[{}] Stream read error: {}", request_id_clone, e));
                    Err(e)
                }
            }
        });

        let body = Body::from_stream(stream);

        let mut response_builder = Response::builder()
            .status(200)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive");

        // Add captured headers
        for (name, value) in response_headers {
            response_builder = response_builder.header(&name, &value);
        }

        Ok(response_builder
            .body(body)
            .unwrap())
    } else {
        // Transform non-streaming response to OpenAI format
        let response_text = response.text().await.unwrap_or_default();

        // Debug logging for raw Anthropic response
        state.debug_log(format!("[{}] [DEBUG] Raw Anthropic response:\n{}", request_id, response_text));

        match serde_json::from_str::<Value>(&response_text) {
            Ok(anthropic_response) => {
                match transform_anthropic_to_openai(&anthropic_response, &openai_request.model, &request_id) {
                    Ok(openai_response) => {
                        state.log(format!("[{}] Successfully transformed to OpenAI format", request_id));

                        // Debug logging for transformed OpenAI response
                        match serde_json::to_string_pretty(&openai_response) {
                            Ok(response_json) => {
                                state.debug_log(format!("[{}] [DEBUG] Transformed OpenAI response:\n{}", request_id, response_json));
                            },
                            Err(e) => {
                                state.debug_log(format!("[{}] [DEBUG] Failed to serialize OpenAI response: {}", request_id, e));
                            }
                        }

                        let mut response_builder = Response::builder()
                            .status(200)
                            .header("Content-Type", "application/json");

                        // Add captured headers
                        for (name, value) in &response_headers {
                            response_builder = response_builder.header(name, value);
                        }

                        Ok(response_builder
                            .body(Body::from(serde_json::to_string(&openai_response).unwrap()))
                            .unwrap())
                    },
                    Err(e) => {
                        state.log(format!("[{}] Transform error: {}", request_id, e));
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            },
            Err(e) => {
                state.log(format!("[{}] Parse error: {}", request_id, e));
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
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

// Get the base model name (without thinking suffix)
fn get_base_model_name(model: &str) -> String {
    if let Some(pos) = model.rfind("-thinking-") {
        model[..pos].to_string()
    } else {
        model.to_string()
    }
}

// Determine thinking budget tokens based on model name
fn get_thinking_budget_tokens(model: &str) -> Option<u32> {
    if model.ends_with("-thinking-low") {
        Some(1024)
    } else if model.ends_with("-thinking-medium") {
        Some(8192)
    } else if model.ends_with("-thinking-high") {
        Some(32768)
    } else {
        None
    }
}

// Check if a model supports thinking
fn supports_thinking(anthropic_model: &str) -> bool {
    matches!(anthropic_model,
        "claude-opus-4-1-20250805" |
        "claude-opus-4-20250514" |
        "claude-sonnet-4-20250514" |
        "claude-3-7-sonnet-20250219"
    )
}

// Transform OpenAI function to Anthropic tool
fn transform_openai_function_to_anthropic_tool(openai_function: &OpenAIFunction) -> Value {
    json!({
        "name": openai_function.name,
        "description": openai_function.description.as_deref().unwrap_or(""),
        "input_schema": openai_function.parameters.as_ref().unwrap_or(&json!({
            "type": "object",
            "properties": {},
            "required": []
        }))
    })
}

// Transform OpenAI tools/functions to Anthropic tools
fn transform_openai_tools_to_anthropic(openai_request: &OpenAIRequest) -> Option<Vec<Value>> {
    let mut anthropic_tools = Vec::new();

    // Handle new tools format
    if let Some(tools) = &openai_request.tools {
        for tool in tools {
            if tool.tool_type == "function" {
                anthropic_tools.push(transform_openai_function_to_anthropic_tool(&tool.function));
            }
        }
    }

    // Handle legacy functions format
    if let Some(functions) = &openai_request.functions {
        for function in functions {
            anthropic_tools.push(transform_openai_function_to_anthropic_tool(function));
        }
    }

    if anthropic_tools.is_empty() {
        None
    } else {
        Some(anthropic_tools)
    }
}

// Transform OpenAI request to Anthropic request
fn transform_openai_to_anthropic(openai_request: &OpenAIRequest) -> AnthropicMessageRequest {
    // Convert messages
    let mut anthropic_messages = Vec::new();
    let mut system_messages = Vec::new();

    for message in &openai_request.messages {
        match message.role.as_str() {
            "system" => {
                // For system messages, we need to extract content parts into system array
                let anthropic_content = message.get_anthropic_content();
                if let Value::Array(content_parts) = anthropic_content {
                    system_messages.extend(content_parts);
                }
            },
            "user" | "assistant" => {
                // For regular messages, preserve the full content structure
                let anthropic_content = message.get_anthropic_content();
                anthropic_messages.push(json!({
                    "role": message.role,
                    "content": anthropic_content
                }));
            },
            _ => {
                // Skip unknown roles
            }
        }
    }

    // Get base model and thinking configuration
    let base_model = get_base_model_name(&openai_request.model);
    let thinking_budget = get_thinking_budget_tokens(&openai_request.model);

    // Handle max_tokens - OpenAI uses optional, Anthropic requires it
    let max_tokens = openai_request.max_tokens.unwrap_or(4096);

    // Validate thinking budget if specified
    let thinking = if let Some(budget) = thinking_budget {
        if supports_thinking(&base_model) && budget < max_tokens {
            Some(ThinkingParameter {
                thinking_type: "enabled".to_string(),
                budget_tokens: budget,
            })
        } else {
            None // Invalid configuration, skip thinking
        }
    } else {
        None
    };

    // Transform tools
    let anthropic_tools = transform_openai_tools_to_anthropic(openai_request);

    AnthropicMessageRequest {
        model: base_model,
        messages: anthropic_messages,
        max_tokens,
        temperature: if thinking.is_some() {
            Some(1.0) // Temperature must be 1.0 when thinking is enabled
        } else {
            openai_request.temperature
        },
        top_p: openai_request.top_p,
        top_k: None, // OpenAI doesn't have top_k
        system: if system_messages.is_empty() { None } else { Some(system_messages) },
        stream: openai_request.stream,
        thinking,
        tools: anthropic_tools,
    }
}

// Transform Anthropic response to OpenAI format
fn transform_anthropic_to_openai(anthropic_response: &Value, original_model: &str, request_id: &str) -> Result<OpenAIResponse, anyhow::Error> {
    let id = format!("chatcmpl-{}", request_id);
    let created = chrono::Utc::now().timestamp() as u64;

    // Extract content from Anthropic response with improved robustness
    let content = if let Some(content_array) = anthropic_response.get("content").and_then(|c| c.as_array()) {
        if content_array.is_empty() {
            "".to_string()
        } else {
            // Combine all text content parts
            let mut text_parts = Vec::new();
            for item in content_array {
                if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                    text_parts.push(text);
                } else if let Some(text) = item.as_str() {
                    // Handle case where content item is just a string
                    text_parts.push(text);
                }
            }
            text_parts.join("")
        }
    } else if let Some(content_str) = anthropic_response.get("content").and_then(|c| c.as_str()) {
        // Handle case where content is a single string
        content_str.to_string()
    } else {
        // Fallback to empty content
        "".to_string()
    };

    // Extract usage information with better error handling
    let usage_info = anthropic_response.get("usage");
    let prompt_tokens = usage_info
        .and_then(|u| u.get("input_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0) as u32;
    let completion_tokens = usage_info
        .and_then(|u| u.get("output_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0) as u32;

    // Determine finish reason with more comprehensive mapping
    let stop_reason = anthropic_response
        .get("stop_reason")
        .and_then(|r| r.as_str())
        .unwrap_or("stop");

    let finish_reason = match stop_reason {
        "end_turn" => "stop",
        "max_tokens" => "length",
        "stop_sequence" => "stop",
        "tool_use" => "tool_calls",
        _ => "stop",
    }.to_string();

    // Create OpenAI message with proper content handling
    let openai_message = OpenAIMessage {
        role: "assistant".to_string(),
        content: serde_json::Value::String(content),
        name: None,
    };

    Ok(OpenAIResponse {
        id,
        object: "chat.completion".to_string(),
        created,
        model: original_model.to_string(),
        choices: vec![OpenAIChoice {
            index: 0,
            message: openai_message,
            finish_reason,
        }],
        usage: OpenAIUsage {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
    })
}

// Transform Anthropic error response to OpenAI error format
fn transform_anthropic_error_to_openai(anthropic_error: &Value) -> Value {
    // Anthropic error format: {"type":"error","error":{"type":"...","message":"..."}}
    // OpenAI error format: {"error":{"message":"...","type":"...","param":null,"code":null}}

    if let Some(error_obj) = anthropic_error.get("error") {
        let message = error_obj.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");

        let error_type = error_obj.get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown_error");

        // Create OpenAI-formatted error response
        json!({
            "error": {
                "message": message,
                "type": error_type,
                "param": null,
                "code": null
            }
        })
    } else {
        // Fallback for unexpected error format
        json!({
            "error": {
                "message": "An error occurred",
                "type": "unknown_error",
                "param": null,
                "code": null
            }
        })
    }
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

    // Force temperature to 1.0 when thinking is enabled
    if request.thinking.is_some() {
        request.temperature = Some(1.0);
    }
}