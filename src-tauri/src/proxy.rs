use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use if_addrs::get_if_addrs;
use chrono;
use chrono::{Duration as ChronoDuration, Utc};
use parking_lot::{Mutex, RwLock};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, HashMap},
    io::Cursor,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;
use tower::ServiceBuilder;

use crate::{log_debug, log_error};
use tower_http::cors::{Any, CorsLayer};
use uuid::Uuid;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

use crate::oauth::OAuthManager;
use crate::storage::TokenStorage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub timestamp: String,
    pub message: String,
}

// Anthropic API configuration (hardcoded - not user configurable)
const ANTHROPIC_VERSION: &str = "2023-06-01";
const ANTHROPIC_BETA: &str =
    "claude-code-20250219,oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14";
const API_BASE: &str = "https://api.anthropic.com";
const REQUEST_TIMEOUT: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    SelfSigned,
    Custom,
}

impl Default for TlsMode {
    fn default() -> Self {
        Self::SelfSigned
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub port: u16,
    pub bind_address: String,
    pub debug_mode: bool,
    pub openai_compatible: bool,
    #[serde(default)]
    pub start_minimized: bool,
    #[serde(default)]
    pub auto_start_proxy: bool,
    #[serde(default)]
    pub launch_on_startup: bool,
    #[serde(default)]
    pub enable_tls: bool,
    #[serde(default)]
    pub tls_mode: TlsMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key_path: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 8081,
            bind_address: "0.0.0.0".to_string(),
            debug_mode: false,
            openai_compatible: false,
            start_minimized: false,
            auto_start_proxy: false,
            launch_on_startup: false,
            enable_tls: false,
            tls_mode: TlsMode::SelfSigned,
            tls_cert_path: None,
            tls_key_path: None,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

// OpenAI API Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIMessage {
    pub role: String,
    pub content: Value, // Can be string or array of content parts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_call: Option<OpenAIMessageFunctionCall>,
}

impl OpenAIMessage {
    /// Extract content in Anthropic format (array of content objects)
    pub fn get_anthropic_content(&self) -> Value {
        match &self.content {
            Value::String(text) => {
                // Simple string -> single text object
                json!([{
                    "type": "text",
                    "text": text
                }])
            }
            Value::Array(parts) => {
                let mut anthropic_parts = Vec::new();
                for part in parts {
                    match part {
                        Value::String(text) => {
                            anthropic_parts.push(json!({
                                "type": "text",
                                "text": text
                            }));
                        }
                        Value::Object(obj) => {
                            // Preserve the object structure, ensuring it has type and text
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
                            anthropic_parts.push(anthropic_obj);
                        }
                        _ => {} // Skip other types
                    }
                }
                Value::Array(anthropic_parts)
            }
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
            }
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
pub struct OpenAIMessageFunctionCall {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIFunction {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIToolCallFunction {
    pub name: String,
    pub arguments: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<OpenAIToolCallFunction>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpenAIFunctionCall {
    Auto(String), // "auto" or "none"
    Named { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenAIToolCallDeltaFunction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenAIToolCallDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub call_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<OpenAIToolCallDeltaFunction>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenAIMessageFunctionCallDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAITool {
    #[serde(rename = "type")]
    pub tool_type: String, // "function"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<OpenAIFunction>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_usage: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OpenAIStop {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIRequest {
    pub model: String,
    pub messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
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
    pub stop: Option<OpenAIStop>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_options: Option<StreamOptions>, // Stream options parameter
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenAIDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<OpenAIToolCallDelta>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_call: Option<OpenAIMessageFunctionCallDelta>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIModelsResponse {
    pub object: String,
    pub data: Vec<OpenAIModel>,
}

#[derive(Debug, Clone)]
struct ModelMetadata {
    context_length: u32,
    max_output_tokens: u32,
    capabilities: serde_json::Value,
}

#[derive(Debug)]
pub struct ProxyServer {
    config: Arc<RwLock<ProxyConfig>>,
    pub token_storage: Arc<TokenStorage>,
    oauth_manager: Arc<TokioMutex<OAuthManager>>,
    client: Client,
    running: Arc<AtomicBool>,
    server_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    token_refresh_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    logs: Arc<Mutex<Vec<LogEntry>>>,
}

impl ProxyServer {
    pub fn new(token_storage: TokenStorage, oauth_manager: Arc<TokioMutex<OAuthManager>>) -> Self {
        // Load saved configuration or use defaults
        let mut initial_config = token_storage
            .load_config()
            .unwrap_or(None)
            .unwrap_or_else(|| ProxyConfig::default());

        if initial_config.enable_tls && initial_config.tls_mode == TlsMode::SelfSigned {
            match token_storage.ensure_self_signed_certificate(Some(&initial_config)) {
                Ok((cert_path, key_path)) => {
                    initial_config.tls_cert_path =
                        Some(cert_path.to_string_lossy().to_string());
                    initial_config.tls_key_path =
                        Some(key_path.to_string_lossy().to_string());
                }
                Err(e) => {
                    eprintln!(
                        "[ProxyServer] Failed to prepare self-signed certificate: {}. Falling back to HTTP.",
                        e
                    );
                    initial_config.enable_tls = false;
                }
            }
        }

        let token_storage = Arc::new(token_storage);

        Self {
            config: Arc::new(RwLock::new(initial_config)),
            token_storage: token_storage.clone(),
            oauth_manager,
            client: Client::builder()
                .timeout(Duration::from_secs(REQUEST_TIMEOUT))
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("Critical error: Failed to create HTTP client: {}", e);
                    panic!("Failed to create HTTP client: {}", e);
                }),
            running: Arc::new(AtomicBool::new(false)),
            server_handle: Arc::new(Mutex::new(None)),
            token_refresh_task: Arc::new(Mutex::new(None)),
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn get_config(&self) -> ProxyConfig {
        self.config.read().clone()
    }

    pub fn update_config(&self, mut new_config: ProxyConfig) -> Result<()> {
        // Validate port
        if new_config.port == 0 {
            return Err(anyhow!("Port cannot be 0. Please provide a valid port number (1-65535)."));
        }

        // Validate bind_address
        if new_config.bind_address.is_empty() {
            return Err(anyhow!("Bind address cannot be empty. Please provide a valid IP address or hostname."));
        }
        // Normalize optional TLS fields
        if matches!(new_config.tls_cert_path.as_ref(), Some(path) if path.trim().is_empty()) {
            new_config.tls_cert_path = None;
        }
        if matches!(new_config.tls_key_path.as_ref(), Some(path) if path.trim().is_empty()) {
            new_config.tls_key_path = None;
        }

        if new_config.enable_tls {
            match new_config.tls_mode {
                TlsMode::SelfSigned => {
                    let (cert_path, key_path) = self
                        .token_storage
                        .ensure_self_signed_certificate(Some(&new_config))?;
                    new_config.tls_cert_path = Some(cert_path.to_string_lossy().to_string());
                    new_config.tls_key_path = Some(key_path.to_string_lossy().to_string());
                }
                TlsMode::Custom => {
                    let cert_path = new_config
                        .tls_cert_path
                        .as_ref()
                        .ok_or_else(|| anyhow!("TLS certificate path is required for custom mode. Please provide a valid certificate file path."))?;
                    let key_path = new_config
                        .tls_key_path
                        .as_ref()
                        .ok_or_else(|| anyhow!("TLS private key path is required for custom mode. Please provide a valid private key file path."))?;

                    // Validate that paths are not empty
                    if cert_path.trim().is_empty() {
                        return Err(anyhow!("TLS certificate path cannot be empty. Please provide a valid certificate file path."));
                    }
                    
                    if key_path.trim().is_empty() {
                        return Err(anyhow!("TLS private key path cannot be empty. Please provide a valid private key file path."));
                    }

                    if !Path::new(cert_path).exists() {
                        return Err(anyhow!(
                            "TLS certificate file not found at {}",
                            cert_path
                        ));
                    }
                    if !Path::new(key_path).exists() {
                        return Err(anyhow!(
                            "TLS private key file not found at {}",
                            key_path
                        ));
                    }
                }
            }
        }

        // Save configuration to file for persistence
        if let Err(e) = self.token_storage.save_config(&new_config) {
            // Log error but don't fail the operation
            self.log_warning(format!("Failed to save configuration: {}", e));
        }

        let mut config = self.config.write();
        *config = new_config;
        Ok(())
    }

    async fn load_tls_config(&self, config: &ProxyConfig) -> Result<RustlsConfig> {
        let cert_path = config
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| anyhow!("TLS certificate path is not configured. Please configure a valid certificate file path."))?;
        let key_path = config
            .tls_key_path
            .as_ref()
            .ok_or_else(|| anyhow!("TLS private key path is not configured. Please configure a valid private key file path."))?;

        let cert_bytes = tokio::fs::read(cert_path)
            .await
            .with_context(|| format!("Failed to read TLS certificate at {}", cert_path))?;
        let key_bytes = tokio::fs::read(key_path)
            .await
            .with_context(|| format!("Failed to read TLS private key at {}", key_path))?;

        let mut cert_reader = Cursor::new(&cert_bytes);
        let cert_chain = certs(&mut cert_reader)
            .map_err(|e| anyhow!("Failed to parse TLS certificate: {}. Please ensure the certificate file is valid and in PEM format.", e))?
            .into_iter()
            .map(Certificate)
            .collect::<Vec<_>>();

        if cert_chain.is_empty() {
            return Err(anyhow!(
                "No certificates found in TLS certificate file at {}",
                cert_path
            ));
        }

        let mut key_reader = Cursor::new(&key_bytes);
        let mut keys = pkcs8_private_keys(&mut key_reader)
            .map_err(|e| anyhow!("Failed to parse PKCS#8 private key: {}. Please ensure the private key file is valid and in PEM format.", e))?;

        if keys.is_empty() {
            let mut key_reader = Cursor::new(&key_bytes);
            keys = rsa_private_keys(&mut key_reader)
                .map_err(|e| anyhow!("Failed to parse RSA private key: {}. Please ensure the private key file is valid and in PEM format.", e))?;
        }

        if keys.is_empty() {
            return Err(anyhow!(
                "No usable private keys found in TLS key file at {}",
                key_path
            ));
        }

        let private_key = PrivateKey(keys.remove(0));

        let mut server_config = ServerConfig::builder()
            .with_cipher_suites(&[
                rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
                rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
                rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ])
            .with_kx_groups(&[
                &rustls::kx_group::X25519,
                &rustls::kx_group::SECP384R1,
                &rustls::kx_group::SECP256R1,
            ])
            .with_protocol_versions(&[
                &rustls::version::TLS12,
                &rustls::version::TLS13,
            ])
            .context("Failed to configure Rustls protocol versions")?
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)?;

        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(RustlsConfig::from_config(Arc::new(server_config)))
    }

    pub fn get_logs(&self) -> Vec<LogEntry> {
        self.logs.lock().clone()
    }

    pub fn clear_logs(&self) {
        self.logs.lock().clear();
    }

    fn log_with_level(&self, level: LogLevel, message: String) {
        let mut logs = self.logs.lock();
        logs.push(LogEntry {
            level,
            timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
            message,
        });

        // Keep only last 1000 log entries
        let len = logs.len();
        if len > 1000 {
            logs.drain(0..len - 1000);
        }
    }

    fn log_warning(&self, message: String) {
        self.log_with_level(LogLevel::Warning, message);
    }

    fn log_info(&self, message: String) {
        self.log_with_level(LogLevel::Info, message);
    }

    fn compute_accessible_endpoints(config: &ProxyConfig) -> Vec<String> {
        let scheme = if config.enable_tls { "https" } else { "http" };
        let port = config.port;
        let bind_address = config.bind_address.trim();

        let mut endpoints: BTreeSet<String> = BTreeSet::new();

        fn add_host(endpoints: &mut BTreeSet<String>, scheme: &str, port: u16, host: &str) {
            if host.is_empty() {
                return;
            }
            let needs_brackets = host.contains(':') && !host.starts_with('[');
            let formatted = if needs_brackets {
                format!("{}://[{}]:{}", scheme, host, port)
            } else {
                format!("{}://{}:{}", scheme, host, port)
            };
            endpoints.insert(formatted);
        }

        fn add_ip(endpoints: &mut BTreeSet<String>, scheme: &str, port: u16, ip: std::net::IpAddr) {
            let formatted = match ip {
                std::net::IpAddr::V4(v4) => format!("{}://{}:{}", scheme, v4, port),
                std::net::IpAddr::V6(v6) => format!("{}://[{}]:{}", scheme, v6, port),
            };
            endpoints.insert(formatted);
        }

        let is_wildcard = bind_address == "0.0.0.0" || bind_address == "::";

        if is_wildcard {
            add_host(&mut endpoints, scheme, port, "localhost");
            add_ip(
                &mut endpoints,
                scheme,
                port,
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            );
            add_ip(
                &mut endpoints,
                scheme,
                port,
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            );

            if let Ok(hostname) = hostname::get() {
                if let Some(name) = hostname.to_str() {
                    add_host(&mut endpoints, scheme, port, name);
                }
            }

            if let Ok(ifaces) = get_if_addrs() {
                for iface in ifaces {
                    let ip = iface.ip();
                    if ip.is_loopback() || ip.is_unspecified() {
                        continue;
                    }
                    if let std::net::IpAddr::V4(v4) = ip {
                        if v4.is_link_local() {
                            continue;
                        }
                    }
                    if let std::net::IpAddr::V6(v6) = ip {
                        if v6.is_unicast_link_local() {
                            continue;
                        }
                    }
                    add_ip(&mut endpoints, scheme, port, ip);
                }
            }
        } else {
            if let Ok(ip) = bind_address.parse::<std::net::IpAddr>() {
                add_ip(&mut endpoints, scheme, port, ip);
            } else {
                add_host(&mut endpoints, scheme, port, bind_address);
            }
            add_host(&mut endpoints, scheme, port, "localhost");
            add_ip(
                &mut endpoints,
                scheme,
                port,
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            );
            add_ip(
                &mut endpoints,
                scheme,
                port,
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            );
        }

        endpoints.into_iter().collect()
    }

    pub fn accessible_endpoints(&self) -> Vec<String> {
        let config = self.get_config();
        Self::compute_accessible_endpoints(&config)
    }

    pub fn get_certificate_path_for_trust(&self) -> Result<PathBuf> {
        let config = self.get_config();
        if !config.enable_tls {
            return Err(anyhow!(
                "TLS is currently disabled. Enable TLS before trusting the certificate."
            ));
        }

        match config.tls_mode {
            TlsMode::SelfSigned => {
                let (cert_path, _) = self
                    .token_storage
                    .ensure_self_signed_certificate(Some(&config))?;
                Ok(cert_path)
            }
            TlsMode::Custom => {
                if let Some(path) = config.tls_cert_path {
                    let path = PathBuf::from(path);
                    if path.exists() {
                        Ok(path)
                    } else {
                        Err(anyhow!(
                            "Configured TLS certificate was not found at {}",
                            path.display()
                        ))
                    }
                } else {
                    Err(anyhow!(
                        "No certificate path configured for custom TLS mode"
                    ))
                }
            }
        }
    }

    pub fn trust_certificate(&self) -> Result<String> {
        let cert_path = self.get_certificate_path_for_trust()?;
        crate::cert::install_certificate(&cert_path)?;
        Ok(format!(
            "Certificate trusted successfully: {}",
            cert_path.display()
        ))
    }

    /// Cancel any scheduled token refresh task
    pub fn cancel_token_refresh(&self) {
        if let Some(handle) = self.token_refresh_task.lock().take() {
            handle.abort();
        }
    }

    /// Schedule automatic token refresh near expiry (60s buffer)
    pub fn schedule_token_refresh(&self) {
        // Cancel existing schedule first
        self.cancel_token_refresh();

        let stored = match self.token_storage.load_tokens() {
            Ok(Some(t)) => t,
            _ => return, // nothing to schedule
        };

        let now = Utc::now();
        let buffer = ChronoDuration::seconds(60);
        let mut wait = stored.expires_at - now - buffer;
        if wait < ChronoDuration::zero() {
            wait = ChronoDuration::zero();
        }

        let initial_sleep = Duration::from_secs(wait.num_seconds().max(0) as u64);
        self.log_info(format!(
            "[Scheduler] Scheduling token refresh in {} seconds (at ~{})",
            initial_sleep.as_secs(),
            (now + wait).format("%Y-%m-%d %H:%M:%S UTC")
        ));

        let token_storage = self.token_storage.clone();
        let oauth_manager = self.oauth_manager.clone();
        let logs = self.logs.clone();

        let handle = tokio::spawn(async move {
            let push_log = |level: LogLevel, msg: String| {
                let mut l = logs.lock();
                l.push(LogEntry {
                    level,
                    timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                    message: msg,
                });
                let len = l.len();
                if len > 1000 {
                    l.drain(0..len - 1000);
                }
            };

            let mut sleep_dur = initial_sleep;
            loop {
                tokio::time::sleep(sleep_dur).await;

                // Acquire refresh token
                let refresh_token = match token_storage.get_refresh_token() {
                    Ok(Some(rt)) => rt,
                    _ => {
                        push_log(LogLevel::Warning, "[Scheduler] No refresh token; stopping".to_string());
                        break;
                    }
                };

                // Refresh with retry
                let mgr = oauth_manager.lock().await;
                match mgr.refresh_token_with_retry(&refresh_token, 3).await {
                    Ok(new_tokens) => {
                        drop(mgr);
                        match token_storage.save_tokens(&new_tokens) {
                            Ok(_) => {
                                push_log(LogLevel::Info, "[Scheduler] ✓ Auto-refreshed tokens".to_string());
                                // Schedule next cycle based on new expiry
                                let secs = new_tokens.expires_in.saturating_sub(60) as u64;
                                sleep_dur = Duration::from_secs(secs);
                                continue;
                            }
                            Err(e) => {
                                push_log(LogLevel::Error, format!("[Scheduler] ✗ Save tokens failed: {}", e));
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        drop(mgr);
                        push_log(LogLevel::Error, format!("[Scheduler] ✗ Refresh failed: {}", e));
                        break;
                    }
                }
            }
        });

        *self.token_refresh_task.lock() = Some(handle);
    }


    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::Relaxed) {
            return Err(anyhow!("Server is already running. Please stop the server before starting it again."));
        }

        let config = self.get_config();
        let addr = format!("{}:{}", config.bind_address, config.port);
        let socket_addr: SocketAddr = addr.parse()?;

        let tls_config = if config.enable_tls {
            Some(self.load_tls_config(&config).await?)
        } else {
            None
        };

        let listener = if config.enable_tls {
            None
        } else {
            Some(TcpListener::bind(&socket_addr).await?)
        };

        let scheme = if config.enable_tls { "https" } else { "http" };
        self.log_info(format!("Proxy server starting on {}://{}", scheme, addr));
        if config.enable_tls {
            let mode_label = match config.tls_mode {
                TlsMode::SelfSigned => "self-signed",
                TlsMode::Custom => "custom",
            };
            if let Some(cert_path) = config.tls_cert_path.as_ref() {
                self.log_info(format!(
                    "TLS enabled ({}) with certificate: {}",
                    mode_label, cert_path
                ));
            } else {
                self.log_info(format!("TLS enabled ({})", mode_label));
            }
        }

        let endpoints_to_log = Self::compute_accessible_endpoints(&config);
        if !endpoints_to_log.is_empty() {
            self.log_info("Accessible endpoints:".to_string());
            for entry in endpoints_to_log {
                self.log_info(format!("  {}", entry));
            }
        }

        let router = self.build_router();
        let router_for_http = router.clone();
        let router_for_tls = router;

        self.running.store(true, Ordering::Relaxed);

        let server_logs = self.logs.clone();
        let server_running = self.running.clone();

        let handle = tokio::spawn(async move {
            let result = match (tls_config, listener) {
                (Some(tls_config), _) => axum_server::bind_rustls(socket_addr, tls_config)
                    .serve(router_for_tls.into_make_service())
                    .await,
                (None, Some(listener)) => {
                    axum::serve(listener, router_for_http.into_make_service()).await
                }
                (None, None) => unreachable!("Server must have either TLS config or HTTP listener"),
            };

            if let Err(e) = result {
                let mut logs = server_logs.lock();
                logs.push(LogEntry {
                    level: LogLevel::Error,
                    timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
                    message: format!("Server error: {}", e),
                });
            }
            server_running.store(false, Ordering::Relaxed);
        });

        *self.server_handle.lock() = Some(handle);
        self.log_info("Proxy server started successfully".to_string());

        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        if !self.running.load(Ordering::Relaxed) {
            return Err(anyhow!("Server is not running. Please start the server before attempting to stop it."));
        }

        self.running.store(false, Ordering::Relaxed);

        if let Some(handle) = self.server_handle.lock().take() {
            handle.abort();
            self.log_info("Proxy server stopped".to_string());
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
                ServiceBuilder::new().layer(
                    CorsLayer::new()
                        .allow_origin(Any)
                        .allow_methods(Any)
                        .allow_headers(Any),
                ),
            )
            .with_state(state)
    }
}

#[derive(Clone)]
struct ProxyState {
    pub token_storage: Arc<TokenStorage>,
    oauth_manager: Arc<TokioMutex<OAuthManager>>,
    client: Client,
    logs: Arc<Mutex<Vec<LogEntry>>>,
    config: Arc<RwLock<ProxyConfig>>,
}

impl ProxyState {
    fn log_with_level(&self, level: LogLevel, message: String) {
        let mut logs = self.logs.lock();
        logs.push(LogEntry {
            level,
            timestamp: chrono::Utc::now().format("%H:%M:%S").to_string(),
            message,
        });

        let len = logs.len();
        if len > 1000 {
            logs.drain(0..len - 1000);
        }
    }

    fn log_error(&self, message: String) {
        self.log_with_level(LogLevel::Error, message);
    }

    fn log_warning(&self, message: String) {
        self.log_with_level(LogLevel::Warning, message);
    }

    fn log_info(&self, message: String) {
        self.log_with_level(LogLevel::Info, message);
    }

    fn log_debug(&self, message: String) {
        // Only log debug messages when debug_mode is enabled
        let config = self.config.read();
        if config.debug_mode {
            drop(config); // Release the lock before calling log_with_level
            self.log_with_level(LogLevel::Debug, message);
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
                self.log_info(format!(
                    "[{}] Access token expired, attempting automatic refresh...",
                    request_id
                ));
            }
            Err(e) => {
                self.log_error(format!(
                    "[{}] Error getting access token: {}",
                    request_id, e
                ));
                return Err(e);
            }
        }

        // Try to get refresh token
        let refresh_token = match self.token_storage.get_refresh_token() {
            Ok(Some(token)) => token,
            Ok(None) => {
                self.log_warning(format!("[{}] No refresh token available", request_id));
                return Ok(None);
            }
            Err(e) => {
                self.log_error(format!(
                    "[{}] Error getting refresh token: {}",
                    request_id, e
                ));
                return Err(e);
            }
        };

        // Attempt to refresh tokens
        let oauth_manager = self.oauth_manager.lock().await;
        match oauth_manager.refresh_token(&refresh_token).await {
            Ok(token_response) => {
                self.log_info(format!("[{}] ✓ Successfully refreshed tokens", request_id));

                // Save the new tokens
                match self.token_storage.save_tokens(&token_response) {
                    Ok(_) => {
                        self.log_info(format!("[{}] ✓ Saved refreshed tokens", request_id));
                        Ok(Some(token_response.access_token))
                    }
                    Err(e) => {
                        self.log_error(format!(
                            "[{}] ✗ Failed to save refreshed tokens: {}",
                            request_id, e
                        ));
                        Err(e)
                    }
                }
            }
            Err(e) => {
                self.log_error(format!("[{}] ✗ Failed to refresh token: {}", request_id, e));
                self.log_info(format!(
                    "[{}] Please re-authenticate using the OAuth flow",
                    request_id
                ));
                Ok(None)
            }
        }
    }
}

// Get model metadata including context length and capabilities
fn get_model_metadata(model_id: &str) -> ModelMetadata {
    let base_model = get_base_model_name(model_id);

    // Context length and max completion tokens based on model
    let (context_length, max_output_tokens) = match base_model.as_str() {
        "claude-opus-4-1-20250805" => (200000, 8192),
        "claude-opus-4-20250514" => (200000, 8192),
        "claude-sonnet-4-5-20250929" => {
            // Sonnet 4.5 supports extended context with beta header
            (200000, 64000) // Standard context, can be up to 1M with beta
        }
        "claude-sonnet-4-20250514" => {
            // Sonnet 4 supports extended context with beta header
            (200000, 8192) // Standard context, can be up to 1M with beta
        }
        "claude-haiku-4-5-20251015" => {
            // Haiku 4.5 - first Haiku with extended thinking and 64K output
            (200000, 64000) // Standard context, 1M available
        }
        "claude-3-haiku-20240307" => (200000, 4096),
        _ => (200000, 4096), // Default for unknown models
    };

    // Build capabilities object
    let mut capabilities = serde_json::Map::new();
    capabilities.insert("completion".to_string(), serde_json::Value::Bool(true));
    capabilities.insert("chat".to_string(), serde_json::Value::Bool(true));
    capabilities.insert("streaming".to_string(), serde_json::Value::Bool(true));

    // Check if model supports thinking
    if supports_thinking(&base_model) {
        capabilities.insert("thinking".to_string(), serde_json::Value::Bool(true));
    }

    // Check if it's a thinking variant
    if model_id.contains("-thinking-") {
        capabilities.insert(
            "thinking_enabled".to_string(),
            serde_json::Value::Bool(true),
        );
        if let Some(budget) = get_thinking_budget_tokens(model_id) {
            capabilities.insert(
                "thinking_budget_tokens".to_string(),
                serde_json::Value::Number(serde_json::Number::from(budget)),
            );
        }
    }

    // Extended context support for Sonnet 4.5, Sonnet 4, and Haiku 4.5
    if base_model == "claude-sonnet-4-5-20250929"
        || base_model == "claude-sonnet-4-20250514"
        || base_model == "claude-haiku-4-5-20251015" {
        capabilities.insert(
            "extended_context".to_string(),
            serde_json::Value::Bool(true),
        );
        capabilities.insert(
            "max_context_length".to_string(),
            serde_json::Value::Number(serde_json::Number::from(1000000)),
        );
    }

    ModelMetadata {
        context_length,
        max_output_tokens,
        capabilities: serde_json::Value::Object(capabilities),
    }
}

async fn handle_models(
    axum::extract::State(state): axum::extract::State<ProxyState>,
) -> Result<Json<OpenAIModelsResponse>, StatusCode> {
    let config = state.config.read();
    if !config.openai_compatible {
        return Err(StatusCode::NOT_FOUND);
    }

    let model_ids = vec![
        // Standard Anthropic models
        "claude-opus-4-1-20250805",
        "claude-opus-4-20250514",
        "claude-sonnet-4-5-20250929",
        "claude-sonnet-4-20250514",
        "claude-haiku-4-5-20251015",
        "claude-3-haiku-20240307",
        // Thinking variants for Claude Opus 4.1
        "claude-opus-4-1-20250805-thinking-low",
        "claude-opus-4-1-20250805-thinking-medium",
        "claude-opus-4-1-20250805-thinking-high",
        // Thinking variants for Claude Opus 4
        "claude-opus-4-20250514-thinking-low",
        "claude-opus-4-20250514-thinking-medium",
        "claude-opus-4-20250514-thinking-high",
        // Thinking variants for Claude Sonnet 4.5
        "claude-sonnet-4-5-20250929-thinking-low",
        "claude-sonnet-4-5-20250929-thinking-medium",
        "claude-sonnet-4-5-20250929-thinking-high",
        // Thinking variants for Claude Sonnet 4
        "claude-sonnet-4-20250514-thinking-low",
        "claude-sonnet-4-20250514-thinking-medium",
        "claude-sonnet-4-20250514-thinking-high",
        // Thinking variants for Claude Haiku 4.5
        "claude-haiku-4-5-20251015-thinking-low",
        "claude-haiku-4-5-20251015-thinking-medium",
        "claude-haiku-4-5-20251015-thinking-high",
    ];

    let models = model_ids
        .into_iter()
        .map(|id| {
            let ModelMetadata {
                context_length,
                max_output_tokens,
                capabilities,
            } = get_model_metadata(id);

            OpenAIModel {
                id: id.to_string(),
                object: "model".to_string(),
                created: 1687882411,
                owned_by: "anthropic".to_string(),
                context_length: Some(context_length),
                max_output_tokens: Some(max_output_tokens),
                capabilities: Some(capabilities),
            }
        })
        .collect();

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

    state.log_info(format!("[{}] Incoming request to /v1/messages", request_id));
    state.log_info(format!(
        "[{}] Model: {}, Stream: {}",
        request_id,
        request.model,
        request.stream.unwrap_or(false)
    ));

    // Get valid access token with automatic refresh
    let access_token = match state.get_valid_access_token(&request_id).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            state.log_warning(format!(
                "[{}] No valid access token available - authentication required",
                request_id
            ));
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            state.log_error(format!(
                "[{}] Token authentication error: {}",
                request_id, e
            ));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Inject Claude Code system message to bypass authentication detection
    inject_claude_code_system_message(&mut request);

    // Sanitize the request
    sanitize_anthropic_request(&mut request);

    // Build the forwarded request with Claude Code headers
    let mut req_builder = state
        .client
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
            state.log_error(format!("[{}] Request failed: {}", request_id, e));
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status = response.status();
    state.log_info(format!(
        "[{}] Anthropic API responded with: {}",
        request_id, status
    ));

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
            .map_err(|e| {
                log_error!("Failed to build streaming response: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?)
    } else {
        // Handle non-streaming response
        let response_text = response.text().await.unwrap_or_default();

        Ok(Response::builder()
            .status(status.as_u16())
            .header("Content-Type", "application/json")
            .body(Body::from(response_text))
            .map_err(|e| {
                log_error!("Failed to build non-streaming response: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?)
    }
}

// Accumulator for usage information across streaming chunks
#[derive(Default)]
struct ToolCallStreamState {
    id: String,
    arguments: String,
}

#[derive(Default)]
struct StreamingTransformState {
    input_tokens: u32,
    output_tokens: u32,
    has_input_tokens: bool,
    has_final_output_tokens: bool,
    tool_calls: HashMap<usize, ToolCallStreamState>,
}

impl StreamingTransformState {
    fn set_input_tokens(&mut self, tokens: u32) {
        if !self.has_input_tokens {
            self.input_tokens = tokens;
            self.has_input_tokens = true;
        }
    }

    fn set_final_output_tokens(&mut self, tokens: u32) {
        self.output_tokens = tokens;
        self.has_final_output_tokens = true;
    }

    fn create_usage_chunk(
        &self,
        request_id: &str,
        original_model: &str,
        created: u64,
    ) -> Option<String> {
        if self.has_input_tokens && self.has_final_output_tokens {
            let total_tokens = self.input_tokens + self.output_tokens;
            let usage_chunk = serde_json::json!({
                "id": format!("chatcmpl-{}", request_id),
                "object": "chat.completion.chunk",
                "created": created,
                "model": original_model,
                "choices": [],
                "usage": {
                    "prompt_tokens": self.input_tokens,
                    "completion_tokens": self.output_tokens,
                    "total_tokens": total_tokens
                }
            });

            let usage_chunk_str = match serde_json::to_string(&usage_chunk) {
                Ok(json) => json,
                Err(e) => {
                    log_error!("Failed to serialize usage chunk: {}", e);
                    return None;
                }
            };

            Some(format!("data: {}\n\n", usage_chunk_str))
        } else {
            None
        }
    }

    fn start_tool_call(&mut self, index: usize, id: String) {
        self.tool_calls.insert(
            index,
            ToolCallStreamState {
                id,
                arguments: String::new(),
            },
        );
    }

    fn append_tool_arguments(&mut self, index: usize, partial: &str) -> Option<(String, String)> {
        if let Some(state) = self.tool_calls.get_mut(&index) {
            state.arguments.push_str(partial);
            Some((state.id.clone(), partial.to_string()))
        } else {
            None
        }
    }

    fn end_tool_call(&mut self, index: usize) {
        self.tool_calls.remove(&index);
    }
}

// Transform Anthropic streaming chunk to OpenAI format
fn transform_anthropic_streaming_chunk(
    chunk: &[u8],
    request_id: &str,
    original_model: &str,
    created: u64,
    state: &mut StreamingTransformState,
    include_usage: bool,
) -> Result<Vec<String>, anyhow::Error> {
    let chunk_str = std::str::from_utf8(chunk)?;
    let mut openai_chunks = Vec::new();

    for event_block in chunk_str.split(
        "

",
    ) {
        if event_block.trim().is_empty() {
            continue;
        }

        let mut event_type = None;
        let mut data_content = None;

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
                                    content: Some(String::new()),
                                    ..Default::default()
                                },
                                finish_reason: None,
                            }],
                        };

                        openai_chunks.push(format!(
                            "data: {}

",
                            serde_json::to_string(&openai_chunk)?
                        ));

                        if let Some(usage) = data_json.get("message").and_then(|m| m.get("usage")) {
                            let input_tokens = usage
                                .get("input_tokens")
                                .and_then(|t| t.as_u64())
                                .unwrap_or(0) as u32;
                            state.set_input_tokens(input_tokens);

                            log_debug!("Stored input_tokens from message_start: {}", input_tokens);
                        }
                    }
                }
                Some("content_block_start") => {
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        let index =
                            data_json.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        if let Some(content_block) = data_json.get("content_block") {
                            if content_block.get("type").and_then(|t| t.as_str())
                                == Some("tool_use")
                            {
                                let tool_id = content_block
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| {
                                        format!("tool_call_{}", Uuid::new_v4().simple())
                                    });
                                let tool_name = content_block
                                    .get("name")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_default();
                                state.start_tool_call(index, tool_id.clone());

                                let delta = OpenAIDelta {
                                    tool_calls: Some(vec![OpenAIToolCallDelta {
                                        id: Some(tool_id.clone()),
                                        call_type: Some("function".to_string()),
                                        function: Some(OpenAIToolCallDeltaFunction {
                                            name: Some(tool_name.clone()),
                                            arguments: Some(String::new()),
                                        }),
                                        extra: HashMap::new(),
                                    }]),
                                    ..Default::default()
                                };

                                let openai_chunk = OpenAIStreamResponse {
                                    id: format!("chatcmpl-{}", request_id),
                                    object: "chat.completion.chunk".to_string(),
                                    created,
                                    model: original_model.to_string(),
                                    choices: vec![OpenAIChoiceDelta {
                                        index: 0,
                                        delta,
                                        finish_reason: None,
                                    }],
                                };

                                openai_chunks.push(format!(
                                    "data: {}

",
                                    serde_json::to_string(&openai_chunk)?
                                ));

                                if let Some(input_value) = content_block.get("input") {
                                    if !input_value.is_null() {
                                        let arguments =
                                            serde_json::to_string(input_value).unwrap_or_default();
                                        if !arguments.is_empty() && arguments != "{}" {
                                            if let Some((tool_id_append, append_value)) =
                                                state.append_tool_arguments(index, &arguments)
                                            {
                                                let delta = OpenAIDelta {
                                                    tool_calls: Some(vec![OpenAIToolCallDelta {
                                                        id: Some(tool_id_append),
                                                        call_type: None,
                                                        function: Some(
                                                            OpenAIToolCallDeltaFunction {
                                                                name: None,
                                                                arguments: Some(append_value),
                                                            },
                                                        ),
                                                        extra: HashMap::new(),
                                                    }]),
                                                    ..Default::default()
                                                };

                                                let openai_chunk = OpenAIStreamResponse {
                                                    id: format!("chatcmpl-{}", request_id),
                                                    object: "chat.completion.chunk".to_string(),
                                                    created,
                                                    model: original_model.to_string(),
                                                    choices: vec![OpenAIChoiceDelta {
                                                        index: 0,
                                                        delta,
                                                        finish_reason: None,
                                                    }],
                                                };

                                                openai_chunks.push(format!(
                                                    "data: {}

",
                                                    serde_json::to_string(&openai_chunk)?
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Some("content_block_delta") => {
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        let index =
                            data_json.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        if let Some(delta) = data_json.get("delta") {
                            if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                                let delta_value = OpenAIDelta {
                                    content: Some(text.to_string()),
                                    ..Default::default()
                                };
                                let openai_chunk = OpenAIStreamResponse {
                                    id: format!("chatcmpl-{}", request_id),
                                    object: "chat.completion.chunk".to_string(),
                                    created,
                                    model: original_model.to_string(),
                                    choices: vec![OpenAIChoiceDelta {
                                        index: 0,
                                        delta: delta_value,
                                        finish_reason: None,
                                    }],
                                };
                                openai_chunks.push(format!(
                                    "data: {}

",
                                    serde_json::to_string(&openai_chunk)?
                                ));
                            }

                            if let Some(partial_json) =
                                delta.get("partial_json").and_then(|t| t.as_str())
                            {
                                if let Some((tool_id, append_value)) =
                                    state.append_tool_arguments(index, partial_json)
                                {
                                    let delta_value = OpenAIDelta {
                                        tool_calls: Some(vec![OpenAIToolCallDelta {
                                            id: Some(tool_id),
                                            call_type: None,
                                            function: Some(OpenAIToolCallDeltaFunction {
                                                name: None,
                                                arguments: Some(append_value),
                                            }),
                                            extra: HashMap::new(),
                                        }]),
                                        ..Default::default()
                                    };

                                    let openai_chunk = OpenAIStreamResponse {
                                        id: format!("chatcmpl-{}", request_id),
                                        object: "chat.completion.chunk".to_string(),
                                        created,
                                        model: original_model.to_string(),
                                        choices: vec![OpenAIChoiceDelta {
                                            index: 0,
                                            delta: delta_value,
                                            finish_reason: None,
                                        }],
                                    };

                                    openai_chunks.push(format!(
                                        "data: {}

",
                                        serde_json::to_string(&openai_chunk)?
                                    ));
                                }
                            }

                            if let Some(input_json) = delta.get("input_json") {
                                let arguments =
                                    serde_json::to_string(input_json).unwrap_or_default();
                                if !arguments.is_empty() {
                                    if let Some((tool_id, append_value)) =
                                        state.append_tool_arguments(index, &arguments)
                                    {
                                        let delta_value = OpenAIDelta {
                                            tool_calls: Some(vec![OpenAIToolCallDelta {
                                                id: Some(tool_id),
                                                call_type: None,
                                                function: Some(OpenAIToolCallDeltaFunction {
                                                    name: None,
                                                    arguments: Some(append_value),
                                                }),
                                                extra: HashMap::new(),
                                            }]),
                                            ..Default::default()
                                        };
                                        let openai_chunk = OpenAIStreamResponse {
                                            id: format!("chatcmpl-{}", request_id),
                                            object: "chat.completion.chunk".to_string(),
                                            created,
                                            model: original_model.to_string(),
                                            choices: vec![OpenAIChoiceDelta {
                                                index: 0,
                                                delta: delta_value,
                                                finish_reason: None,
                                            }],
                                        };
                                        openai_chunks.push(format!(
                                            "data: {}

",
                                            serde_json::to_string(&openai_chunk)?
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                Some("content_block_stop") => {
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        let index =
                            data_json.get("index").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                        state.end_tool_call(index);
                    }
                }
                Some("message_delta") => {
                    if let Ok(data_json) = serde_json::from_str::<Value>(data) {
                        if let Some(stop_reason) = data_json
                            .get("delta")
                            .and_then(|d| d.get("stop_reason"))
                            .and_then(|s| s.as_str())
                        {
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
                                    delta: OpenAIDelta::default(),
                                    finish_reason: Some(finish_reason.to_string()),
                                }],
                            };

                            openai_chunks.push(format!(
                                "data: {}

",
                                serde_json::to_string(&openai_chunk)?
                            ));
                        }

                        if let Some(usage) = data_json.get("usage") {
                            let output_tokens = usage
                                .get("output_tokens")
                                .and_then(|t| t.as_u64())
                                .unwrap_or(0)
                                as u32;
                            state.set_final_output_tokens(output_tokens);

                            log_debug!("Stored final output_tokens from message_delta: {}", output_tokens);
                        }
                    }
                }
                Some("message_stop") => {
                    if include_usage {
                        if let Some(usage_chunk) =
                            state.create_usage_chunk(request_id, original_model, created)
                        {
                            openai_chunks.push(usage_chunk);
                            log_debug!("Emitted final complete usage chunk at stream end (include_usage=true)");
                            log_debug!("Final usage: prompt={}, completion={}, total={}", state.input_tokens, state.output_tokens, state.input_tokens + state.output_tokens);
                        }
                    } else {
                        log_debug!("Usage chunk NOT emitted (include_usage=false)");
                    }

                    openai_chunks.push(
                        "data: [DONE]

"
                        .to_string(),
                    );
                }
                _ => {
                    // Skip unknown events
                }
            }
        }
    }

    Ok(openai_chunks)
}

async fn handle_openai_chat_impl(
    axum::extract::State(state): axum::extract::State<ProxyState>,
    headers: HeaderMap,
    Json(mut openai_request): Json<OpenAIRequest>,
) -> Result<Response, StatusCode> {
    let openai_compatible = {
        let config = state.config.read();
        config.openai_compatible
    };

    if !openai_compatible {
        return Err(StatusCode::NOT_FOUND);
    }

    let request_id = Uuid::new_v4().to_string()[..8].to_string();
    state.log_info(format!(
        "[{}] OpenAI compatible request to /v1/chat/completions",
        request_id
    ));
    state.log_info(format!(
        "[{}] Model: {}, Stream: {}, StreamOptions: {:?}",
        request_id,
        openai_request.model,
        openai_request.stream.unwrap_or(false),
        openai_request.stream_options
    ));

    // Log all incoming request headers
    state.log_debug(format!(
        "[{}] [DEBUG] Incoming request headers:",
        request_id
    ));
    for (name, value) in headers.iter() {
        if let Ok(value_str) = value.to_str() {
            state.log_debug(format!(
                "[{}] [DEBUG]   {}: {}",
                request_id,
                name.as_str(),
                value_str
            ));
        } else {
            state.log_debug(format!(
                "[{}] [DEBUG]   {}: <non-utf8>",
                request_id,
                name.as_str()
            ));
        }
    }

    // Debug logging for request body
    match serde_json::to_string_pretty(&openai_request) {
        Ok(request_json) => {
            state.log_debug(format!(
                "[{}] [DEBUG] OpenAI request body:\n{}",
                request_id, request_json
            ));
        }
        Err(e) => {
            state.log_debug(format!(
                "[{}] [DEBUG] Failed to serialize request body: {}",
                request_id, e
            ));
        }
    }

    let ModelMetadata {
        context_length: _,
        max_output_tokens,
        capabilities: _,
    } = get_model_metadata(&openai_request.model);

    if let Some(n) = openai_request.n {
        if n > 1 {
            state.log_warning(format!(
                "[{}] Rejecting request with unsupported n value: {}",
                request_id, n
            ));
            return Ok(openai_invalid_request_response(
                "This OpenAI-compatible proxy only supports n=1 completions",
                Some("n"),
                Some("unsupported_feature"),
            ));
        }
    }

    if let Some(freq) = openai_request.frequency_penalty {
        if freq != 0.0 {
            state.log_warning(format!(
                "[{}] Rejecting request with unsupported frequency_penalty: {}",
                request_id, freq
            ));
            return Ok(openai_invalid_request_response(
                "frequency_penalty is not supported for Anthropic-backed models",
                Some("frequency_penalty"),
                Some("unsupported_feature"),
            ));
        }
    }

    if let Some(presence) = openai_request.presence_penalty {
        if presence != 0.0 {
            state.log_warning(format!(
                "[{}] Rejecting request with unsupported presence_penalty: {}",
                request_id, presence
            ));
            return Ok(openai_invalid_request_response(
                "presence_penalty is not supported for Anthropic-backed models",
                Some("presence_penalty"),
                Some("unsupported_feature"),
            ));
        }
    }

    let requested_max = openai_request
        .max_output_tokens
        .or(openai_request.max_tokens);
    let resolved_max_tokens = match requested_max {
        Some(0) => {
            state.log_warning(format!(
                "[{}] Rejecting request with max_tokens=0",
                request_id
            ));
            return Ok(openai_invalid_request_response(
                "max_tokens must be greater than zero",
                Some("max_tokens"),
                Some("invalid_request_error"),
            ));
        }
        Some(value) if value > max_output_tokens => {
            state.log_warning(format!(
                "[{}] Rejecting request exceeding max_output_tokens ({} > {})",
                request_id, value, max_output_tokens
            ));
            return Ok(openai_invalid_request_response(
                &format!(
                    "Requested max_tokens {} exceeds this model's max_output_tokens {}",
                    value, max_output_tokens
                ),
                Some("max_tokens"),
                Some("max_output_tokens_exceeded"),
            ));
        }
        Some(value) => value,
        None => std::cmp::min(max_output_tokens, 4096),
    };
    openai_request.max_tokens = Some(resolved_max_tokens);
    openai_request.max_output_tokens = Some(resolved_max_tokens);
    state.log_debug(format!(
        "[{}] Using max_tokens={} (model max_output_tokens={})",
        request_id, resolved_max_tokens, max_output_tokens
    ));

    let mut stop_sequences = openai_request.stop.as_ref().map(|stop| match stop {
        OpenAIStop::Single(value) => vec![value.clone()],
        OpenAIStop::Multiple(values) => values.clone(),
    }).map(|mut seqs| {
        seqs.retain(|s| !s.is_empty());
        if seqs.len() > 4 {
            seqs.truncate(4);
        }
        seqs
    });
    if let Some(seqs) = stop_sequences.as_ref() {
        if seqs.is_empty() {
            stop_sequences = None;
        }
    }
    if let Some(seqs) = stop_sequences.as_ref() {
        state.log_debug(format!(
            "[{}] Normalized stop_sequences: {:?}",
            request_id, seqs
        ));
    }

    // Transform OpenAI request to Anthropic format
    let mut anthropic_request =
        transform_openai_to_anthropic(&openai_request, stop_sequences);

    // Get access token
    let access_token = match state.get_valid_access_token(&request_id).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            state.log_warning(format!(
                "[{}] No valid access token - authentication required",
                request_id
            ));
            return Err(StatusCode::UNAUTHORIZED);
        }
        Err(e) => {
            state.log_error(format!("[{}] Token error: {}", request_id, e));
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Inject Claude Code system message and sanitize
    inject_claude_code_system_message(&mut anthropic_request);
    sanitize_anthropic_request(&mut anthropic_request);

    // Debug logging for transformed Anthropic request
    match serde_json::to_string_pretty(&anthropic_request) {
        Ok(request_json) => {
            state.log_debug(format!(
                "[{}] [DEBUG] Transformed Anthropic request body:\n{}",
                request_id, request_json
            ));
        }
        Err(e) => {
            state.log_debug(format!(
                "[{}] [DEBUG] Failed to serialize Anthropic request body: {}",
                request_id, e
            ));
        }
    }

    // Make request to Anthropic API
    let mut req_builder = state
        .client
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

    // Log outgoing request headers to Anthropic
    state.log_debug(format!(
        "[{}] [DEBUG] Outgoing Anthropic request to {}/v1/messages?beta=true",
        request_id, API_BASE
    ));
    state.log_debug(format!(
        "[{}] [DEBUG] Outgoing headers to Anthropic:",
        request_id
    ));
    state.log_debug(format!(
        "[{}] [DEBUG]   Authorization: Bearer <redacted>",
        request_id
    ));
    state.log_debug(format!(
        "[{}] [DEBUG]   Content-Type: application/json",
        request_id
    ));
    state.log_debug(format!(
        "[{}] [DEBUG]   anthropic-version: {}",
        request_id, ANTHROPIC_VERSION
    ));
    state.log_debug(format!(
        "[{}] [DEBUG]   anthropic-beta: {}",
        request_id, ANTHROPIC_BETA
    ));
    state.log_debug(format!(
        "[{}] [DEBUG]   User-Agent: claude-cli/1.0.113 (external, cli)",
        request_id
    ));
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(user_agent_str) = user_agent.to_str() {
            state.log_debug(format!(
                "[{}] [DEBUG]   X-Forwarded-User-Agent: {}",
                request_id, user_agent_str
            ));
        }
    }

    let response = match req_builder.json(&anthropic_request).send().await {
        Ok(resp) => resp,
        Err(e) => {
            state.log_error(format!("[{}] Request failed: {}", request_id, e));
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status = response.status();
    state.log_info(format!(
        "[{}] Anthropic API response: {}",
        request_id, status
    ));

    // Log all incoming response headers from Anthropic
    state.log_debug(format!(
        "[{}] [DEBUG] Anthropic response headers:",
        request_id
    ));
    for (name, value) in response.headers().iter() {
        if let Ok(value_str) = value.to_str() {
            state.log_debug(format!(
                "[{}] [DEBUG]   {}: {}",
                request_id,
                name.as_str(),
                value_str
            ));
        } else {
            state.log_debug(format!(
                "[{}] [DEBUG]   {}: <non-utf8>",
                request_id,
                name.as_str()
            ));
        }
    }

    // Capture important headers before consuming the response
    let mut response_headers = Vec::new();
    for (name, value) in response.headers().iter() {
        let header_name = name.as_str();
        if header_name.starts_with("x-anthropic-ratelimit-")
            || header_name.starts_with("anthropic-ratelimit-")
            || header_name == "x-request-id"
            || header_name == "anthropic-request-id"
        {
            if let Ok(value_str) = value.to_str() {
                response_headers.push((header_name.to_string(), value_str.to_string()));
            }
        }
    }

    if !status.is_success() {
        // Handle error response - transform to OpenAI format
        let error_text = response.text().await.unwrap_or_default();
        state.log_error(format!(
            "[{}] Anthropic API error ({}): {}",
            request_id, status, &error_text
        ));

        // Debug logging for raw Anthropic error response
        state.log_debug(format!(
            "[{}] [DEBUG] Raw Anthropic error response:\n{}",
            request_id, error_text
        ));

        // Try to parse and transform the error to OpenAI format
        let openai_error = match serde_json::from_str::<Value>(&error_text) {
            Ok(anthropic_error) => {
                // Check if it's an Anthropic error format
                if anthropic_error.get("type").and_then(|t| t.as_str()) == Some("error") {
                    state.log_debug(format!(
                        "[{}] [DEBUG] Transforming Anthropic error to OpenAI format",
                        request_id
                    ));
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
            }
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
                state.log_debug(format!(
                    "[{}] [DEBUG] Transformed OpenAI error:\n{}",
                    request_id, error_json
                ));
            }
            Err(e) => {
                state.log_debug(format!(
                    "[{}] [DEBUG] Failed to serialize OpenAI error: {}",
                    request_id, e
                ));
            }
        }

        let mut response_builder = Response::builder()
            .status(status.as_u16())
            .header("Content-Type", "application/json");

        // Add captured headers
        for (name, value) in response_headers.iter() {
            response_builder = response_builder.header(name.as_str(), value.as_str());
        }

        // Log outgoing error response headers to client
        state.log_debug(format!(
            "[{}] [DEBUG] Outgoing error response headers to client:",
            request_id
        ));
        state.log_debug(format!(
            "[{}] [DEBUG]   Status: {}",
            request_id,
            status.as_u16()
        ));
        state.log_debug(format!(
            "[{}] [DEBUG]   Content-Type: application/json",
            request_id
        ));
        for (name, value) in &response_headers {
            state.log_debug(format!("[{}] [DEBUG]   {}: {}", request_id, name, value));
        }

        return Ok(response_builder
            .body(Body::from(
                serde_json::to_string(&openai_error).unwrap_or_else(|_| error_text),
            ))
            .map_err(|e| {
                log_error!("Failed to build error response: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?);
    }

    if openai_request.stream.unwrap_or(false) {
        // Transform streaming response from Anthropic to OpenAI format
        state.log_info(format!(
            "[{}] Streaming response with OpenAI transformation",
            request_id
        ));
        state.log_debug(format!(
            "[{}] [DEBUG] Starting stream transformation",
            request_id
        ));

        let created = chrono::Utc::now().timestamp() as u64;
        let original_model = openai_request.model.clone();
        let request_id_clone = request_id.to_string();
        let state_clone = state.clone();

        // Check if client requested usage statistics in streaming response
        let include_usage = openai_request
            .stream_options
            .as_ref()
            .and_then(|opts| opts.include_usage)
            .unwrap_or(false);

        state.log_debug(format!(
            "[{}] [DEBUG] stream_options.include_usage = {}",
            request_id, include_usage
        ));

        // Create a stream that transforms Anthropic chunks to OpenAI format with stateful usage tracking
        let transform_state = Arc::new(parking_lot::Mutex::new(StreamingTransformState::default()));
        let transform_state_clone = transform_state.clone();

        let stream = response.bytes_stream().map(move |chunk_result| {
            match chunk_result {
                Ok(chunk) => {
                    state_clone.log_debug(format!("[{}] [DEBUG] Processing chunk: {} bytes", request_id_clone, chunk.len()));

                    // Log raw chunk data (first 500 chars for readability)
                    let chunk_str = std::str::from_utf8(&chunk).unwrap_or("<non-utf8>");
                    let preview = if chunk_str.len() > 500 {
                        format!("{}... [truncated]", &chunk_str[..500])
                    } else {
                        chunk_str.to_string()
                    };
                    state_clone.log_debug(format!("[{}] [DEBUG] Raw chunk content: {}", request_id_clone, preview));

                    let mut state_guard = transform_state_clone.lock();

                    // Log streaming state before processing
                    state_clone.log_debug(format!("[{}] [DEBUG] Streaming state before: input_tokens={}, output_tokens={}, has_input={}, has_final_output={}",
                        request_id_clone,
                        state_guard.input_tokens,
                        state_guard.output_tokens,
                        state_guard.has_input_tokens,
                        state_guard.has_final_output_tokens
                    ));

                    match transform_anthropic_streaming_chunk(&chunk, &request_id_clone, &original_model, created, &mut *state_guard, include_usage) {
                        Ok(openai_chunks) => {
                            state_clone.log_debug(format!("[{}] [DEBUG] Transformed to {} OpenAI chunks", request_id_clone, openai_chunks.len()));

                            // Log each transformed chunk
                            for (i, openai_chunk) in openai_chunks.iter().enumerate() {
                                let preview = if openai_chunk.len() > 300 {
                                    format!("{}... [truncated]", &openai_chunk[..300])
                                } else {
                                    openai_chunk.clone()
                                };
                                state_clone.log_debug(format!("[{}] [DEBUG] OpenAI chunk {}: {}", request_id_clone, i, preview));
                            }

                            // Log streaming state after processing
                            state_clone.log_debug(format!("[{}] [DEBUG] Streaming state after: input_tokens={}, output_tokens={}, has_input={}, has_final_output={}",
                                request_id_clone,
                                state_guard.input_tokens,
                                state_guard.output_tokens,
                                state_guard.has_input_tokens,
                                state_guard.has_final_output_tokens
                            ));

                            let combined = openai_chunks.join("");
                            Ok(bytes::Bytes::from(combined))
                        }
                        Err(e) => {
                            state_clone.log_error(format!("[{}] Stream transformation error: {}", request_id_clone, e));
                            // Forward original chunk on error
                            Ok(chunk)
                        }
                    }
                }
                Err(e) => {
                    state_clone.log_error(format!("[{}] Stream read error: {}", request_id_clone, e));
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
        for (name, value) in response_headers.iter() {
            response_builder = response_builder.header(name.as_str(), value.as_str());
        }

        // Log outgoing streaming response headers to client
        state.log_debug(format!(
            "[{}] [DEBUG] Outgoing streaming response headers to client:",
            request_id
        ));
        state.log_debug(format!("[{}] [DEBUG]   Status: 200", request_id));
        state.log_debug(format!(
            "[{}] [DEBUG]   Content-Type: text/event-stream",
            request_id
        ));
        state.log_debug(format!(
            "[{}] [DEBUG]   Cache-Control: no-cache",
            request_id
        ));
        state.log_debug(format!("[{}] [DEBUG]   Connection: keep-alive", request_id));
        for (name, value) in &response_headers {
            state.log_debug(format!("[{}] [DEBUG]   {}: {}", request_id, name, value));
        }

        Ok(response_builder.body(body).map_err(|e| {
                log_error!("Failed to build OpenAI streaming response: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?)
    } else {
        // Transform non-streaming response to OpenAI format
        let response_text = response.text().await.unwrap_or_default();

        // Debug logging for raw Anthropic response
        state.log_debug(format!(
            "[{}] [DEBUG] Raw Anthropic response:\n{}",
            request_id, response_text
        ));

        match serde_json::from_str::<Value>(&response_text) {
            Ok(anthropic_response) => {
                match transform_anthropic_to_openai(
                    &anthropic_response,
                    &openai_request.model,
                    &request_id,
                ) {
                    Ok(openai_response) => {
                        state.log_info(format!(
                            "[{}] Successfully transformed to OpenAI format",
                            request_id
                        ));

                        // Debug log the transformed usage
                        log_debug!("Transformed OpenAI response usage: prompt={}, completion={}, total={}",
                            openai_response.usage.prompt_tokens,
                            openai_response.usage.completion_tokens,
                            openai_response.usage.total_tokens
                        );

                        // Debug logging for transformed OpenAI response
                        match serde_json::to_string_pretty(&openai_response) {
                            Ok(response_json) => {
                                state.log_debug(format!(
                                    "[{}] [DEBUG] Transformed OpenAI response:\n{}",
                                    request_id, response_json
                                ));
                            }
                            Err(e) => {
                                state.log_debug(format!(
                                    "[{}] [DEBUG] Failed to serialize OpenAI response: {}",
                                    request_id, e
                                ));
                            }
                        }

                        let mut response_builder = Response::builder()
                            .status(200)
                            .header("Content-Type", "application/json");

                        // Add captured headers
                        for (name, value) in &response_headers {
                            response_builder = response_builder.header(name, value);
                        }

                        // Log outgoing non-streaming response headers to client
                        state.log_debug(format!(
                            "[{}] [DEBUG] Outgoing non-streaming response headers to client:",
                            request_id
                        ));
                        state.log_debug(format!("[{}] [DEBUG]   Status: 200", request_id));
                        state.log_debug(format!(
                            "[{}] [DEBUG]   Content-Type: application/json",
                            request_id
                        ));
                        for (name, value) in &response_headers {
                            state.log_debug(format!(
                                "[{}] [DEBUG]   {}: {}",
                                request_id, name, value
                            ));
                        }

                        let response_body = match serde_json::to_string(&openai_response) {
                            Ok(json) => json,
                            Err(e) => {
                                log_error!("Failed to serialize OpenAI response: {}", e);
                                return Err(StatusCode::INTERNAL_SERVER_ERROR);
                            }
                        };

                        Ok(response_builder
                            .body(Body::from(response_body))
                            .map_err(|e| {
                                log_error!("Failed to build OpenAI response: {}", e);
                                StatusCode::INTERNAL_SERVER_ERROR
                            })?)
                    }
                    Err(e) => {
                        state.log_error(format!("[{}] Transform error: {}", request_id, e));
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    }
                }
            }
            Err(e) => {
                state.log_error(format!("[{}] Parse error: {}", request_id, e));
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
        })),
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
    matches!(
        anthropic_model,
        "claude-opus-4-1-20250805"
            | "claude-opus-4-20250514"
            | "claude-sonnet-4-5-20250929"
            | "claude-sonnet-4-20250514"
            | "claude-haiku-4-5-20251015"
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
                if let Some(function) = &tool.function {
                    anthropic_tools.push(transform_openai_function_to_anthropic_tool(function));
                }
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
fn transform_openai_to_anthropic(
    openai_request: &OpenAIRequest,
    stop_sequences: Option<Vec<String>>,
) -> AnthropicMessageRequest {
    // Convert messages
    let mut anthropic_messages = Vec::new();
    let mut system_messages = Vec::new();

    for message in &openai_request.messages {
        match message.role.as_str() {
            "system" => {
                let anthropic_content = message.get_anthropic_content();
                if let Value::Array(content_parts) = anthropic_content {
                    system_messages.extend(content_parts);
                }
            }
            "user" => {
                let anthropic_content = message.get_anthropic_content();
                anthropic_messages.push(json!({
                    "role": "user",
                    "content": anthropic_content
                }));
            }
            "assistant" => {
                let mut content_parts = Vec::new();
                match message.get_anthropic_content() {
                    Value::Array(parts) => {
                        content_parts.extend(parts);
                    }
                    Value::Object(obj) => {
                        content_parts.push(Value::Object(obj));
                    }
                    Value::Null => {}
                    other => {
                        content_parts.push(other);
                    }
                }

                if let Some(tool_calls) = &message.tool_calls {
                    for call in tool_calls {
                        if call.call_type == "function" {
                            if let Some(function) = &call.function {
                                let input_value = parse_function_arguments(&function.arguments);
                                let tool_use = json!({
                                    "type": "tool_use",
                                    "id": call.id,
                                    "name": function.name,
                                    "input": input_value
                                });
                                content_parts.push(tool_use);
                            }
                        }
                    }
                } else if let Some(function_call) = &message.function_call {
                    let generated_id = format!("function_call_{}", Uuid::new_v4().simple());
                    let input_value = parse_function_arguments(&function_call.arguments);
                    let tool_use = json!({
                        "type": "tool_use",
                        "id": generated_id,
                        "name": function_call.name,
                        "input": input_value
                    });
                    content_parts.push(tool_use);
                }

                anthropic_messages.push(json!({
                    "role": "assistant",
                    "content": Value::Array(content_parts)
                }));
            }
            "tool" => {
                if let Some(tool_call_id) = &message.tool_call_id {
                    let tool_result_content = message.get_anthropic_content();
                    let mut tool_result = json!({
                        "type": "tool_result",
                        "tool_use_id": tool_call_id,
                        "content": tool_result_content
                    });
                    if let Some(name) = &message.name {
                        if let Value::Object(obj) = &mut tool_result {
                            obj.insert("name".to_string(), Value::String(name.clone()));
                        }
                    }
                    anthropic_messages.push(json!({
                        "role": "user",
                        "content": [tool_result]
                    }));
                } else {
                    let anthropic_content = message.get_anthropic_content();
                    anthropic_messages.push(json!({
                        "role": "user",
                        "content": anthropic_content
                    }));
                }
            }
            _ => {
                // Skip unsupported roles quietly
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
    let anthropic_tool_choice = openai_request
        .tool_choice
        .as_ref()
        .and_then(map_openai_tool_choice);

    let metadata = openai_request
        .user
        .as_ref()
        .map(|user| json!({ "user_id": user, "source": "maxproxy-openai-compat" }));

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
        system: if system_messages.is_empty() {
            None
        } else {
            Some(system_messages)
        },
        stream: openai_request.stream,
        thinking,
        tools: anthropic_tools,
        tool_choice: anthropic_tool_choice,
        stop_sequences,
        metadata,
    }
}

// Transform Anthropic response to OpenAI format
fn transform_anthropic_to_openai(
    anthropic_response: &Value,
    original_model: &str,
    request_id: &str,
) -> Result<OpenAIResponse, anyhow::Error> {
    let id = format!("chatcmpl-{}", request_id);
    let created = chrono::Utc::now().timestamp() as u64;

    let mut aggregated_text = String::new();
    let mut content_parts: Vec<Value> = Vec::new();
    let mut tool_calls: Vec<OpenAIToolCall> = Vec::new();
    let mut has_structured_content = false;

    if let Some(content_array) = anthropic_response.get("content").and_then(|c| c.as_array()) {
        for item in content_array {
            match item.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                        aggregated_text.push_str(text);
                        content_parts.push(json!({"type": "text", "text": text}));
                    }
                }
                Some("tool_use") => {
                    has_structured_content = true;
                    let tool_id = item
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("tool_call_{}", Uuid::new_v4().simple()));
                    let tool_name = item
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_default();
                    let input_value = item
                        .get("input")
                        .cloned()
                        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
                    let arguments =
                        serde_json::to_string(&input_value).unwrap_or_else(|_| "{}".to_string());
                    let tool_call = OpenAIToolCall {
                        id: tool_id,
                        call_type: "function".to_string(),
                        function: Some(OpenAIToolCallFunction {
                            name: tool_name,
                            arguments,
                        }),
                        extra: HashMap::new(),
                    };
                    tool_calls.push(tool_call);
                }
                _ => {
                    let fallback = if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                        text.to_string()
                    } else {
                        serde_json::to_string(item).unwrap_or_default()
                    };
                    if !fallback.is_empty() {
                        has_structured_content = true;
                        aggregated_text.push_str(&fallback);
                        content_parts.push(json!({"type": "text", "text": fallback}));
                    }
                }
            }
        }
    } else if let Some(content_str) = anthropic_response.get("content").and_then(|c| c.as_str()) {
        aggregated_text.push_str(content_str);
    }

    let content_value = if !tool_calls.is_empty() || has_structured_content {
        if content_parts.is_empty() {
            Value::String(aggregated_text.clone())
        } else {
            Value::Array(content_parts.clone())
        }
    } else {
        Value::String(aggregated_text.clone())
    };

    let usage_info = anthropic_response.get("usage");
    let prompt_tokens = usage_info
        .and_then(|u| u.get("input_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0) as u32;
    let completion_tokens = usage_info
        .and_then(|u| u.get("output_tokens"))
        .and_then(|t| t.as_u64())
        .unwrap_or(0) as u32;

    log_debug!("Non-streaming response usage: prompt={}, completion={}, total={}",
        prompt_tokens,
        completion_tokens,
        prompt_tokens + completion_tokens
    );

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
    }
    .to_string();

    let openai_message = OpenAIMessage {
        role: "assistant".to_string(),
        content: content_value,
        name: None,
        tool_calls: if tool_calls.is_empty() {
            None
        } else {
            Some(tool_calls)
        },
        tool_call_id: None,
        function_call: None,
    };

    Ok(OpenAIResponse {
        id,
        object: "chat.completion".to_string(),
        created,
        model: original_model.to_string(),
        choices: vec![OpenAIChoice {
            index: 0,
            message: openai_message,
            finish_reason: Some(finish_reason),
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
        let message = error_obj
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");

        let error_type = error_obj
            .get("type")
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

fn openai_invalid_request_response(
    message: &str,
    param: Option<&str>,
    code: Option<&str>,
) -> Response {
    let mut error_payload = serde_json::Map::new();
    error_payload.insert("message".to_string(), Value::String(message.to_string()));
    error_payload.insert(
        "type".to_string(),
        Value::String("invalid_request_error".to_string()),
    );
    error_payload.insert(
        "param".to_string(),
        param
            .map(|p| Value::String(p.to_string()))
            .unwrap_or(Value::Null),
    );
    error_payload.insert(
        "code".to_string(),
        code.map(|c| Value::String(c.to_string()))
            .unwrap_or(Value::Null),
    );

    let mut root = serde_json::Map::new();
    root.insert("error".to_string(), Value::Object(error_payload));

    let body = Value::Object(root);

    (StatusCode::BAD_REQUEST, Json(body)).into_response()
}

fn parse_function_arguments(arguments: &str) -> Value {
    if arguments.trim().is_empty() {
        return Value::Object(serde_json::Map::new());
    }

    match serde_json::from_str::<Value>(arguments) {
        Ok(Value::Object(map)) => Value::Object(map),
        Ok(Value::Array(array)) => Value::Array(array),
        Ok(Value::Null) => Value::Object(serde_json::Map::new()),
        Ok(other) => {
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("value".to_string(), other);
            Value::Object(wrapper)
        }
        Err(_) => {
            let mut wrapper = serde_json::Map::new();
            wrapper.insert("value".to_string(), Value::String(arguments.to_string()));
            Value::Object(wrapper)
        }
    }
}

fn map_openai_tool_choice(choice: &Value) -> Option<Value> {
    match choice {
        Value::Object(obj) => {
            if let Some(Value::String(choice_type)) = obj.get("type") {
                match choice_type.as_str() {
                    "function" => {
                        if let Some(Value::Object(function_obj)) = obj.get("function") {
                            if let Some(Value::String(name)) = function_obj.get("name") {
                                return Some(json!({
                                    "type": "tool",
                                    "name": name
                                }));
                            }
                        }
                        None
                    }
                    "tool" => Some(Value::Object(obj.clone())),
                    _ => None,
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

fn inject_claude_code_system_message(request: &mut AnthropicMessageRequest) {
    // Count existing cache_control blocks so we stay within Anthropic's limit of 4
    let existing_cache_control_blocks = count_cache_control_blocks(request);

    // The exact spoof message from Claude Code - must be first system message
    let mut claude_code_spoof_element = json!({
        "type": "text",
        "text": "You are Claude Code, Anthropic's official CLI for Claude."
    });

    // Only add cache_control metadata if it will not exceed the API limit
    if existing_cache_control_blocks < 4 {
        if let Value::Object(obj) = &mut claude_code_spoof_element {
            obj.insert(
                "cache_control".to_string(),
                json!({"type": "ephemeral"}),
            );
        }
    }

    // Claude Code uses array format for system messages
    if let Some(existing_system) = &mut request.system {
        // Prepend our spoof element to the existing system array
        existing_system.insert(0, claude_code_spoof_element);
    } else {
        // No existing system message - create array with just the spoof
        request.system = Some(vec![claude_code_spoof_element]);
    }
}

fn count_cache_control_blocks(request: &AnthropicMessageRequest) -> usize {
    fn count_in_value(value: &Value) -> usize {
        match value {
            Value::Object(map) => {
                let mut count = if map.contains_key("cache_control") { 1 } else { 0 };
                for inner_value in map.values() {
                    count += count_in_value(inner_value);
                }
                count
            }
            Value::Array(items) => items.iter().map(count_in_value).sum(),
            _ => 0,
        }
    }

    let mut total = 0;

    if let Some(system_messages) = &request.system {
        for message in system_messages {
            total += count_in_value(message);
        }
    }

    for message in &request.messages {
        total += count_in_value(message);
    }

    total
}

fn sanitize_content_value(value: &mut Value) -> bool {
    match value {
        Value::Array(items) => {
            items.retain_mut(|item| sanitize_content_value(item));
            !items.is_empty()
        }
        Value::Object(map) => {
            let is_text_block = matches!(
                map.get("type").and_then(|v| v.as_str()),
                Some("text") | None
            );

            if is_text_block {
                map.get("text")
                    .and_then(|t| t.as_str())
                    .map(|text| !text.trim().is_empty())
                    .unwrap_or(false)
            } else {
                if let Some(content_value) = map.get_mut("content") {
                    if !sanitize_content_value(content_value) {
                        return false;
                    }
                }
                true
            }
        }
        Value::String(text) => !text.trim().is_empty(),
        Value::Null => false,
        _ => true,
    }
}

fn sanitize_message_value(message: &mut Value) -> bool {
    if let Value::Object(map) = message {
        if let Some(content) = map.get_mut("content") {
            if !sanitize_content_value(content) {
                return false;
            }
        }
    }
    true
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

    if let Some(system_messages) = &mut request.system {
        system_messages.retain_mut(|message| sanitize_content_value(message));
        if system_messages.is_empty() {
            request.system = None;
        }
    }

    request.messages.retain_mut(|message| sanitize_message_value(message));
}
use futures_util::StreamExt;
