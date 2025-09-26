use anyhow::{anyhow, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::oauth::TokenResponse;
use crate::proxy::ProxyConfig;

const APP_DIR: &str = ".maxproxy";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStatus {
    pub has_tokens: bool,
    pub is_expired: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub time_until_expiry: String,
}

#[derive(Debug)]
pub struct TokenStorage {
    app_dir: PathBuf,
    // Cache to avoid repeated disk reads
    cache: RwLock<Option<StoredToken>>,
}

impl TokenStorage {
    pub fn new() -> Result<Self> {
        let home_dir =
            dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;

        let app_dir = home_dir.join(APP_DIR);

        // Ensure the app directory exists
        if !app_dir.exists() {
            fs::create_dir_all(&app_dir)?;
            println!("[TokenStorage] Created app directory: {:?}", app_dir);
        }

        println!("[TokenStorage] Using storage directory: {:?}", app_dir);

        Ok(Self { app_dir, cache: RwLock::new(None) })
    }

    /// Save tokens to file
    pub fn save_tokens(&self, token_response: &TokenResponse) -> Result<()> {
        println!("[TokenStorage] Attempting to save tokens...");
        println!(
            "[TokenStorage] Token expires in: {} seconds",
            token_response.expires_in
        );

        let expires_at = Utc::now() + Duration::seconds(token_response.expires_in as i64);
        println!("[TokenStorage] Token will expire at: {}", expires_at);

        let stored_token = StoredToken {
            access_token: token_response.access_token.clone(),
            refresh_token: token_response.refresh_token.clone(),
            expires_at,
            token_type: token_response.token_type.clone(),
        };

        let token_file = self.get_token_file_path();
        let token_json = serde_json::to_string_pretty(&stored_token)?;

        println!("[TokenStorage] Saving to file: {:?}", token_file);

        match fs::write(&token_file, &token_json) {
            Ok(_) => {
                println!("[TokenStorage] V Successfully saved tokens to file");
                // Update cache with latest tokens
                if let Ok(mut guard) = self.cache.write() {
                    *guard = Some(stored_token);
                }
                Ok(())
            }
            Err(e) => {
                println!("[TokenStorage] ? Failed to save tokens to file: {}", e);
                Err(anyhow!("Failed to save tokens to file: {}", e))
            }
        }
    }

    /// Load tokens from file (uses in-memory cache when available)
    pub fn load_tokens(&self) -> Result<Option<StoredToken>> {
        // Serve from cache if present
        if let Ok(guard) = self.cache.read() {
            if let Some(tok) = guard.as_ref() {
                return Ok(Some(tok.clone()));
            }
        }

        let token_file = self.get_token_file_path();

        println!(
            "[TokenStorage] Attempting to load tokens from: {:?}",
            token_file
        );

        if !token_file.exists() {
            println!("[TokenStorage] ? No token file found");
            return Ok(None);
        }

        match fs::read_to_string(&token_file) {
            Ok(token_json) => {
                println!(
                    "[TokenStorage] V Successfully read token file (length: {} chars)",
                    token_json.len()
                );

                match serde_json::from_str::<StoredToken>(&token_json) {
                    Ok(stored_token) => {
                        let now = Utc::now();
                        let is_expired = now >= stored_token.expires_at;
                        println!("[TokenStorage] V Successfully parsed token data");
                        println!(
                            "[TokenStorage] Token expires at: {}",
                            stored_token.expires_at
                        );
                        println!("[TokenStorage] Current time: {}", now);
                        println!("[TokenStorage] Token expired: {}", is_expired);
                        // Populate cache
                        if let Ok(mut guard) = self.cache.write() {
                            *guard = Some(stored_token.clone());
                        }
                        Ok(Some(stored_token))
                    }
                    Err(e) => {
                        println!("[TokenStorage] ? Failed to parse token data: {}", e);
                        Err(anyhow!("Failed to parse token data: {}", e))
                    }
                }
            }
            Err(e) => {
                println!("[TokenStorage] ? Failed to read token file: {}", e);
                Err(anyhow!("Failed to read token file: {}", e))
            }
        }
    }

    /// Clear stored tokens
    pub fn clear_tokens(&self) -> Result<()> {
        let token_file = self.get_token_file_path();
        println!(
            "[TokenStorage] Attempting to clear tokens from: {:?}",
            token_file
        );

        if token_file.exists() {
            match fs::remove_file(&token_file) {
                Ok(_) => {
                    println!("[TokenStorage] V Successfully cleared token file");
                    if let Ok(mut guard) = self.cache.write() {
                        *guard = None;
                    }
                    Ok(())
                }
                Err(e) => {
                    println!("[TokenStorage] ? Failed to clear token file: {}", e);
                    Err(anyhow!("Failed to clear token file: {}", e))
                }
            }
        } else {
            println!("[TokenStorage] ? No token file to clear");
            if let Ok(mut guard) = self.cache.write() {
                *guard = None;
            }
            Ok(())
        }
    }

    /// Check if stored token is expired
    pub fn is_token_expired(&self) -> Result<bool> {
        match self.load_tokens()? {
            Some(stored_token) => {
                // Add 60 second buffer before expiry
                let buffer_time = Utc::now() + Duration::seconds(60);
                Ok(buffer_time >= stored_token.expires_at)
            }
            None => Ok(true),
        }
    }

    /// Get the current access token if valid
    pub fn get_access_token(&self) -> Result<Option<String>> {
        if self.is_token_expired()? {
            return Ok(None);
        }

        match self.load_tokens()? {
            Some(stored_token) => Ok(Some(stored_token.access_token)),
            None => Ok(None),
        }
    }

    /// Get the refresh token
    pub fn get_refresh_token(&self) -> Result<Option<String>> {
        match self.load_tokens()? {
            Some(stored_token) => Ok(Some(stored_token.refresh_token)),
            None => Ok(None),
        }
    }

    /// Get token status without exposing secrets
    pub fn get_status(&self) -> Result<TokenStatus> {
        match self.load_tokens()? {
            Some(stored_token) => {
                // Avoid a second disk read: compute directly here with a 60s buffer
                let now = Utc::now();
                let is_expired = (now + Duration::seconds(60)) >= stored_token.expires_at;
                let time_until_expiry = if is_expired {
                    "Expired".to_string()
                } else {
                    let duration = stored_token.expires_at - now;
                    if duration.num_hours() > 0 {
                        format!("{}h {}m", duration.num_hours(), duration.num_minutes() % 60)
                    } else {
                        format!("{}m", duration.num_minutes())
                    }
                };

                Ok(TokenStatus {
                    has_tokens: true,
                    is_expired,
                    expires_at: Some(stored_token.expires_at),
                    time_until_expiry,
                })
            }
            None => Ok(TokenStatus {
                has_tokens: false,
                is_expired: true,
                expires_at: None,
                time_until_expiry: "No tokens available".to_string(),
            }),
        }
    }

    /// Get the token file path
    pub fn get_token_file_path(&self) -> PathBuf {
        self.app_dir.join("tokens.json")
    }

    /// Get the configuration file path
    pub fn get_config_file_path(&self) -> PathBuf {
        self.app_dir.join("config.json")
    }

    /// Save proxy configuration to file
    pub fn save_config(&self, config: &ProxyConfig) -> Result<()> {
        let config_file = self.get_config_file_path();
        let config_json = serde_json::to_string_pretty(config)?;
        fs::write(&config_file, config_json)?;
        println!("[TokenStorage] V Saved configuration to: {:?}", config_file);
        Ok(())
    }

    /// Load proxy configuration from file
    pub fn load_config(&self) -> Result<Option<ProxyConfig>> {
        let config_file = self.get_config_file_path();

        if !config_file.exists() {
            return Ok(None);
        }

        match fs::read_to_string(&config_file) {
            Ok(content) => {
                let config: ProxyConfig = serde_json::from_str(&content)?;
                println!(
                    "[TokenStorage] V Loaded configuration from: {:?}",
                    config_file
                );
                Ok(Some(config))
            }
            Err(e) => Err(anyhow!("Failed to load configuration: {}", e)),
        }
    }
}
