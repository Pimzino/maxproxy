use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;
use webbrowser;

// OAuth configuration constants (from ccmaxproxy settings)
const AUTH_BASE_AUTHORIZE: &str = "https://claude.ai";
const AUTH_BASE_TOKEN: &str = "https://console.anthropic.com";
const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";
const SCOPES: &str = "org:create_api_key user:profile user:inference";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PKCEParams {
    pub code_verifier: String,
    pub code_challenge: String,
    pub state: String,
}

#[derive(Debug)]
pub struct OAuthManager {
    client: reqwest::Client,
    pkce_params: Option<PKCEParams>,
}

impl OAuthManager {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            pkce_params: None,
        }
    }

    /// Generate PKCE code verifier and challenge (plan.md section 3.1)
    pub fn generate_pkce(&mut self) -> Result<PKCEParams> {
        // Generate high-entropy code_verifier (43-128 chars)
        let code_verifier = general_purpose::URL_SAFE_NO_PAD.encode(
            &rand::thread_rng().gen::<[u8; 32]>()
        );

        // Create code_challenge using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let challenge_bytes = hasher.finalize();
        let code_challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // OpenCode uses the verifier as the state
        let state = code_verifier.clone();

        let pkce_params = PKCEParams {
            code_verifier,
            code_challenge,
            state,
        };

        self.pkce_params = Some(pkce_params.clone());
        Ok(pkce_params)
    }

    /// Construct OAuth authorize URL with PKCE (plan.md section 3.2)
    pub fn get_authorize_url(&mut self) -> Result<String> {
        let pkce = self.generate_pkce()?;

        let mut url = Url::parse(&format!("{}/oauth/authorize", AUTH_BASE_AUTHORIZE))?;

        let mut params = HashMap::new();
        params.insert("code", "true"); // Critical parameter from OpenCode
        params.insert("client_id", CLIENT_ID);
        params.insert("response_type", "code");
        params.insert("redirect_uri", REDIRECT_URI);
        params.insert("scope", SCOPES);
        params.insert("code_challenge", &pkce.code_challenge);
        params.insert("code_challenge_method", "S256");
        params.insert("state", &pkce.state);

        let query_string = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        url.set_query(Some(&query_string));
        Ok(url.to_string())
    }

    /// Start the OAuth login flow by opening browser (plan.md section 3.3)
    pub async fn start_login_flow(&mut self) -> Result<String> {
        let auth_url = self.get_authorize_url()?;

        // Open the authorization URL in the default browser
        if let Err(e) = webbrowser::open(&auth_url) {
            eprintln!("Failed to open browser: {}", e);
            // Return URL anyway so user can manually open it
        }

        Ok(auth_url)
    }

    /// Exchange authorization code for tokens (plan.md section 3.4)
    pub async fn exchange_code(&self, code: &str) -> Result<TokenResponse> {
        let pkce_params = self.pkce_params.as_ref()
            .ok_or_else(|| anyhow!("No PKCE parameters available. Call start_login_flow first."))?;

        // Split the code and state (they come as "code#state")
        let parts: Vec<&str> = code.split('#').collect();
        let actual_code = parts.get(0).ok_or_else(|| anyhow!("Invalid code format"))?;
        let received_state = parts.get(1).copied().unwrap_or(&pkce_params.state);

        // Verify state
        if received_state != &pkce_params.state {
            return Err(anyhow!("State mismatch: expected {}, got {}", pkce_params.state, received_state));
        }

        // Prepare token exchange request - match Python implementation exactly
        let mut params = serde_json::Map::new();
        params.insert("code".to_string(), serde_json::Value::String(actual_code.to_string()));
        params.insert("state".to_string(), serde_json::Value::String(received_state.to_string()));
        params.insert("grant_type".to_string(), serde_json::Value::String("authorization_code".to_string()));
        params.insert("client_id".to_string(), serde_json::Value::String(CLIENT_ID.to_string()));
        params.insert("redirect_uri".to_string(), serde_json::Value::String(REDIRECT_URI.to_string()));
        params.insert("code_verifier".to_string(), serde_json::Value::String(pkce_params.code_verifier.clone()));

        let response = self
            .client
            .post(&format!("{}/v1/oauth/token", AUTH_BASE_TOKEN))
            .json(&serde_json::Value::Object(params))
            .header("Content-Type", "application/json")
            .header("User-Agent", "MaxProxy/1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token exchange failed with status {}: {}", status, error_text));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response)
    }

    /// Refresh access token using refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse> {
        let mut params = serde_json::Map::new();
        params.insert("grant_type".to_string(), serde_json::Value::String("refresh_token".to_string()));
        params.insert("client_id".to_string(), serde_json::Value::String(CLIENT_ID.to_string()));
        params.insert("refresh_token".to_string(), serde_json::Value::String(refresh_token.to_string()));

        let response = self
            .client
            .post(&format!("{}/v1/oauth/token", AUTH_BASE_TOKEN))
            .json(&serde_json::Value::Object(params))
            .header("Content-Type", "application/json")
            .header("User-Agent", "MaxProxy/1.0")
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token refresh failed with status {}: {}", status, error_text));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response)
    }
}