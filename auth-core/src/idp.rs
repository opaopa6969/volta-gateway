//! IdP (Identity Provider) client — OIDC communication with Google, GitHub, Microsoft, etc.
//! 1:1 from Java OidcService + IdpProvider.

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;

/// PKCE pair — opaque verifier the client keeps server-side, plus the SHA-256
/// challenge that travels to the IdP in `?code_challenge=`.
///
/// Per RFC 7636, the verifier is 43-128 chars from `[A-Z a-z 0-9 -._~]`; we
/// generate it from 32 random bytes base64-url-encoded (43 chars, no padding).
#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    /// Generate a fresh PKCE verifier + S256 challenge.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let digest = Sha256::digest(verifier.as_bytes());
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        Self { verifier, challenge }
    }
}

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
    ///
    /// Back-compat shim: callers that don't yet support PKCE still get a working
    /// URL, but they miss the anti-injection guarantee — prefer
    /// [`IdpClient::authorization_url_pkce`] in new code.
    pub fn authorization_url(&self, redirect_uri: &str, state: &str, nonce: &str) -> String {
        self.authorization_url_pkce(redirect_uri, state, nonce, None)
    }

    /// Build the authorization URL including PKCE `code_challenge` / `code_challenge_method`
    /// when a challenge is supplied (Backlog P0 #1).
    pub fn authorization_url_pkce(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: Option<&str>,
    ) -> String {
        self.authorization_url_impl(redirect_uri, state, nonce, code_challenge)
    }

    fn authorization_url_impl(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: Option<&str>,
    ) -> String {
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
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("client_id", &self.config.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("response_type", "code")
                .append_pair("scope", &scopes)
                .append_pair("state", state)
                .append_pair("nonce", nonce);
            if let Some(challenge) = code_challenge {
                pairs
                    .append_pair("code_challenge", challenge)
                    .append_pair("code_challenge_method", "S256");
            }
        }
        url.to_string()
    }

    /// Exchange authorization code for tokens.
    ///
    /// Back-compat shim — does not attach `code_verifier`. New callers should
    /// use [`IdpClient::exchange_code_pkce`] so the token exchange proves the
    /// original PKCE proof-of-possession.
    pub async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<TokenResponse, String> {
        self.exchange_code_pkce(code, redirect_uri, None).await
    }

    /// Exchange the authorization code for tokens, optionally attaching
    /// `code_verifier` to satisfy the PKCE challenge (Backlog P0 #1).
    pub async fn exchange_code_pkce(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse, String> {
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
        if let Some(v) = code_verifier {
            params.insert("code_verifier", v);
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_pair_is_rfc7636_shaped() {
        let p = PkcePair::generate();
        // 32 random bytes → 43 base64-url chars, no padding.
        assert_eq!(p.verifier.len(), 43);
        assert!(p.verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        // SHA-256 → 32 bytes → 43 base64-url chars, no padding.
        assert_eq!(p.challenge.len(), 43);
    }

    #[test]
    fn pkce_challenge_matches_verifier_sha256() {
        let p = PkcePair::generate();
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, expected);
    }

    #[test]
    fn pkce_pairs_are_unique() {
        let a = PkcePair::generate();
        let b = PkcePair::generate();
        assert_ne!(a.verifier, b.verifier);
    }

    fn test_client() -> IdpClient {
        IdpClient::new(IdpConfig {
            provider: "google".into(),
            client_id: "cid".into(),
            client_secret: "cs".into(),
            issuer_url: None,
            auth_url: None,
            token_url: None,
            userinfo_url: None,
            scopes: vec![],
        })
    }

    #[test]
    fn authorization_url_without_pkce_omits_challenge() {
        let url = test_client().authorization_url("https://app/cb", "s", "n");
        assert!(!url.contains("code_challenge"));
    }

    #[test]
    fn authorization_url_with_pkce_includes_s256() {
        let url = test_client().authorization_url_pkce("https://app/cb", "s", "n", Some("CHAL"));
        assert!(url.contains("code_challenge=CHAL"));
        assert!(url.contains("code_challenge_method=S256"));
    }
}
