//! IdP (Identity Provider) client — OIDC communication with Google, GitHub, Microsoft, etc.
//! 1:1 from Java OidcService + IdpProvider.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// IdP provider configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdpConfig {
    pub provider: String,          // google, github, microsoft, linkedin, apple
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: Option<String>, // OIDC discovery URL
    pub auth_url: Option<String>,   // Override for non-standard IdPs
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scopes: Vec<String>,
}

/// User info returned from IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpUserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
}

/// IdP client for OAuth2/OIDC operations.
pub struct IdpClient {
    config: IdpConfig,
    http: reqwest::Client,
}

impl IdpClient {
    pub fn new(config: IdpConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    /// Build authorization URL for OIDC redirect.
    pub fn authorization_url(&self, redirect_uri: &str, state: &str, nonce: &str) -> String {
        let auth_url = self.config.auth_url.clone().unwrap_or_else(|| {
            match self.config.provider.as_str() {
                "google" => "https://accounts.google.com/o/oauth2/v2/auth".into(),
                "github" => "https://github.com/login/oauth/authorize".into(),
                "microsoft" => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
                "linkedin" => "https://www.linkedin.com/oauth/v2/authorization".into(),
                "apple" => "https://appleid.apple.com/auth/authorize".into(),
                _ => "".into(),
            }
        });

        let scopes = if self.config.scopes.is_empty() {
            match self.config.provider.as_str() {
                "google" => "openid email profile".into(),
                "github" => "read:user user:email".into(),
                "microsoft" => "openid email profile".into(),
                _ => "openid email profile".into(),
            }
        } else {
            self.config.scopes.join(" ")
        };

        let mut url = Url::parse(&auth_url).unwrap_or_else(|_| Url::parse("https://example.com").unwrap());
        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes)
            .append_pair("state", state)
            .append_pair("nonce", nonce);

        url.to_string()
    }

    /// Exchange authorization code for tokens.
    pub async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<TokenResponse, String> {
        let token_url = self.config.token_url.clone().unwrap_or_else(|| {
            match self.config.provider.as_str() {
                "google" => "https://oauth2.googleapis.com/token".into(),
                "github" => "https://github.com/login/oauth/access_token".into(),
                "microsoft" => "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
                "linkedin" => "https://www.linkedin.com/oauth/v2/accessToken".into(),
                "apple" => "https://appleid.apple.com/auth/token".into(),
                _ => "".into(),
            }
        });

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);
        params.insert("client_id", &self.config.client_id);
        params.insert("client_secret", &self.config.client_secret);

        let resp = self.http.post(&token_url)
            .form(&params)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("token exchange failed: {}", e))?;

        let status = resp.status(); if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("token exchange error {}: {}", status, body));
        }

        resp.json::<TokenResponse>().await
            .map_err(|e| format!("token parse error: {}", e))
    }

    /// Fetch user info from IdP.
    pub async fn userinfo(&self, access_token: &str) -> Result<IdpUserInfo, String> {
        let userinfo_url = self.config.userinfo_url.clone().unwrap_or_else(|| {
            match self.config.provider.as_str() {
                "google" => "https://www.googleapis.com/oauth2/v3/userinfo".into(),
                "github" => "https://api.github.com/user".into(),
                "microsoft" => "https://graph.microsoft.com/v1.0/me".into(),
                _ => "".into(),
            }
        });

        let resp = self.http.get(&userinfo_url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("userinfo failed: {}", e))?;

        let status = resp.status(); if !status.is_success() {
            return Err(format!("userinfo error: {}", resp.status()));
        }

        // GitHub has different field names
        if self.config.provider == "github" {
            let gh: GitHubUser = resp.json().await
                .map_err(|e| format!("github user parse: {}", e))?;
            return Ok(IdpUserInfo {
                sub: gh.id.to_string(),
                email: gh.email,
                name: gh.name,
                picture: gh.avatar_url,
                email_verified: Some(true),
            });
        }

        resp.json::<IdpUserInfo>().await
            .map_err(|e| format!("userinfo parse: {}", e))
    }

    pub fn provider(&self) -> &str { &self.config.provider }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: Option<String>,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}
