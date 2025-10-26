use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::oauth::TokenResponse;
use crate::proxy::ProxyConfig;
use crate::{log_error, log_info};

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
            dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory. Please ensure your system has a valid home directory configured."))?;

        let app_dir = home_dir.join(APP_DIR);

        // Ensure the app directory exists
        if !app_dir.exists() {
            fs::create_dir_all(&app_dir)?;
            log_info!("Created app directory: {:?}", app_dir);
        }

        log_info!("Using storage directory: {:?}", app_dir);

        Ok(Self { app_dir, cache: RwLock::new(None) })
    }

    /// Save tokens to file
    pub fn save_tokens(&self, token_response: &TokenResponse) -> Result<()> {
        log_info!("Attempting to save tokens...");
        log_info!("Token expires in: {} seconds", token_response.expires_in);

        let expires_at = Utc::now() + Duration::seconds(token_response.expires_in as i64);
        log_info!("Token will expire at: {}", expires_at);

        let stored_token = StoredToken {
            access_token: token_response.access_token.clone(),
            refresh_token: token_response.refresh_token.clone(),
            expires_at,
            token_type: token_response.token_type.clone(),
        };

        let token_file = self.get_token_file_path();
        let token_json = serde_json::to_string_pretty(&stored_token)?;

        log_info!("Saving to file: {:?}", token_file);

        match fs::write(&token_file, &token_json) {
            Ok(_) => {
                log_info!("V Successfully saved tokens to file");
                // Update cache with latest tokens
                if let Ok(mut guard) = self.cache.write() {
                    *guard = Some(stored_token);
                }
                Ok(())
            }
            Err(e) => {
                log_error!("? Failed to save tokens to file: {}", e);
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

        log_info!("Attempting to load tokens from: {:?}", token_file);

        if !token_file.exists() {
            log_info!("? No token file found");
            return Ok(None);
        }

        match fs::read_to_string(&token_file) {
            Ok(token_json) => {
                log_info!("V Successfully read token file (length: {} chars)", token_json.len());

                match serde_json::from_str::<StoredToken>(&token_json) {
                    Ok(stored_token) => {
                        let now = Utc::now();
                        let is_expired = now >= stored_token.expires_at;
                        log_info!("V Successfully parsed token data");
                        log_info!("Token expires at: {}", stored_token.expires_at);
                        log_info!("Current time: {}", now);
                        log_info!("Token expired: {}", is_expired);
                        // Populate cache
                        if let Ok(mut guard) = self.cache.write() {
                            *guard = Some(stored_token.clone());
                        }
                        Ok(Some(stored_token))
                    }
                    Err(e) => {
                        log_error!("? Failed to parse token data: {}", e);
                        Err(anyhow!("Failed to parse token data: {}", e))
                    }
                }
            }
            Err(e) => {
                log_error!("? Failed to read token file: {}", e);
                Err(anyhow!("Failed to read token file: {}", e))
            }
        }
    }

    /// Clear stored tokens
    pub fn clear_tokens(&self) -> Result<()> {
        let token_file = self.get_token_file_path();
        log_info!("Attempting to clear tokens from: {:?}", token_file);

        if token_file.exists() {
            match fs::remove_file(&token_file) {
                Ok(_) => {
                    log_info!("V Successfully cleared token file");
                    if let Ok(mut guard) = self.cache.write() {
                        *guard = None;
                    }
                    Ok(())
                }
                Err(e) => {
                    log_error!("? Failed to clear token file: {}", e);
                    Err(anyhow!("Failed to clear token file: {}", e))
                }
            }
        } else {
            log_info!("? No token file to clear");
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

    pub fn get_self_signed_certificate_paths(&self) -> (PathBuf, PathBuf) {
        let tls_dir = self.app_dir.join("tls");
        (tls_dir.join("selfsigned.crt"), tls_dir.join("selfsigned.key"))
    }

    pub fn ensure_self_signed_certificate(
        &self,
        config: Option<&ProxyConfig>,
    ) -> Result<(PathBuf, PathBuf)> {
        let tls_dir = self.app_dir.join("tls");
        if !tls_dir.exists() {
            fs::create_dir_all(&tls_dir)
                .with_context(|| format!("Failed to create TLS directory at {:?}", tls_dir))?;
        }

        let (cert_path, key_path) = self.get_self_signed_certificate_paths();
        let meta_path = tls_dir.join("selfsigned.meta.json");

        let mut dns_set: std::collections::BTreeSet<String> =
            std::collections::BTreeSet::new();
        let mut ip_set: std::collections::BTreeSet<IpAddr> =
            std::collections::BTreeSet::new();

        dns_set.insert("localhost".to_string());
        dns_set.insert("127.0.0.1".to_string());
        dns_set.insert("::1".to_string());
        ip_set.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        ip_set.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));

        if let Some(cfg) = config {
            let bind = cfg.bind_address.trim();
            if !bind.is_empty() && bind != "0.0.0.0" && bind != "::" {
                if let Ok(ip) = bind.parse::<IpAddr>() {
                    if !ip.is_unspecified() {
                        ip_set.insert(ip);
                    }
                } else {
                    dns_set.insert(bind.to_string());
                }
            }
        }

        if let Ok(hostname) = hostname::get() {
            if let Some(name) = hostname.to_str() {
                dns_set.insert(name.to_string());
            }
        }

        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for iface in ifaces {
                let ip = iface.ip();
                if ip.is_loopback() || ip.is_unspecified() {
                    continue;
                }
                if let IpAddr::V4(v4) = ip {
                    if v4.is_link_local() {
                        continue;
                    }
                }
                if let IpAddr::V6(v6) = ip {
                    if v6.is_unicast_link_local() {
                        continue;
                    }
                }
                ip_set.insert(ip);
            }
        }

        #[derive(Serialize, Deserialize)]
        struct SelfSignedMeta {
            dns_names: Vec<String>,
            ip_addrs: Vec<String>,
        }

        let desired_dns_vec: Vec<String> = dns_set.iter().cloned().collect();
        let desired_ip_vec: Vec<String> = ip_set.iter().map(|ip| ip.to_string()).collect();
        let desired_dns_set: std::collections::BTreeSet<String> =
            desired_dns_vec.iter().cloned().collect();
        let desired_ip_set: std::collections::BTreeSet<String> =
            desired_ip_vec.iter().cloned().collect();

        let desired_meta = SelfSignedMeta {
            dns_names: desired_dns_vec,
            ip_addrs: desired_ip_vec,
        };

        let mut needs_regenerate = true;
        if cert_path.exists() && key_path.exists() && meta_path.exists() {
            if let Ok(meta_json) = fs::read_to_string(&meta_path) {
                if let Ok(existing_meta) = serde_json::from_str::<SelfSignedMeta>(&meta_json) {
                    let existing_dns: std::collections::BTreeSet<String> =
                        existing_meta.dns_names.into_iter().collect();
                    let existing_ips: std::collections::BTreeSet<String> =
                        existing_meta.ip_addrs.into_iter().collect();
                    if existing_dns == desired_dns_set && existing_ips == desired_ip_set {
                        needs_regenerate = false;
                    }
                }
            }
        }

        if needs_regenerate {
            log_info!("Generating new self-signed certificate at {:?}", tls_dir);

            let mut params = rcgen::CertificateParams::new(Vec::new());
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "MaxProxy Self-Signed");
            params.subject_alt_names = dns_set
                .iter()
                .cloned()
                .map(|name| rcgen::SanType::DnsName(name.into()))
                .collect();
            for ip in &ip_set {
                params
                    .subject_alt_names
                    .push(rcgen::SanType::IpAddress(*ip));
            }
            if params.subject_alt_names.is_empty() {
                params
                    .subject_alt_names
                    .push(rcgen::SanType::DnsName("localhost".into()));
            }

            let certificate = rcgen::Certificate::from_params(params)
                .context("Failed to create certificate parameters")?;
            let cert_pem = certificate
                .serialize_pem()
                .context("Failed to serialize certificate")?;
            let key_pem = certificate.serialize_private_key_pem();

            fs::write(&cert_path, cert_pem)
                .with_context(|| format!("Failed to write certificate to {:?}", cert_path))?;
            fs::write(&key_path, key_pem)
                .with_context(|| format!("Failed to write private key to {:?}", key_path))?;

            let meta_json = serde_json::to_string_pretty(&desired_meta)?;
            fs::write(&meta_path, meta_json)
                .with_context(|| format!("Failed to write certificate metadata to {:?}", meta_path))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(metadata) = fs::metadata(&key_path) {
                    let mut permissions = metadata.permissions();
                    permissions.set_mode(0o600);
                    if let Err(e) = fs::set_permissions(&key_path, permissions) {
                        log_error!("Failed to set private key permissions: {}", e);
                    }
                }
            }
        }

        Ok((cert_path, key_path))
    }

    /// Save proxy configuration to file
    pub fn save_config(&self, config: &ProxyConfig) -> Result<()> {
        let config_file = self.get_config_file_path();
        let config_json = serde_json::to_string_pretty(config)?;
        fs::write(&config_file, config_json)?;
        log_info!("V Saved configuration to: {:?}", config_file);
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
                log_info!("V Loaded configuration from: {:?}", config_file);
                Ok(Some(config))
            }
            Err(e) => Err(anyhow!("Failed to load configuration: {}", e)),
        }
    }
}
