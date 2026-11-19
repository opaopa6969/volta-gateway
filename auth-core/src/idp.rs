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
        Self {
            verifier,
            challenge,
        }
    }
}

/// IdP provider configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdpConfig {
    pub provider: String, // google, github, microsoft, linkedin, apple
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: Option<String>, // OIDC discovery URL
    pub auth_url: Option<String>,   // Override for non-standard IdPs
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scopes: Vec<String>,
    /// JWKS endpoint for `id_token` verification. Filled by OIDC discovery;
    /// when absent the verifier falls back to `<issuer>/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Label for the login button ("<name> でログイン"). `None` → derived from
    /// `provider` (google → Google, …, unknown → SSO).
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Subset of an OIDC discovery document
/// (`<issuer>/.well-known/openid-configuration`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// Fetch `<issuer>/.well-known/openid-configuration`.
pub async fn discover(issuer: &str) -> Result<OidcDiscovery, String> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("OIDC discovery failed ({url}): {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("OIDC discovery failed ({url}): {}", resp.status()));
    }
    resp.json::<OidcDiscovery>()
        .await
        .map_err(|e| format!("OIDC discovery parse error ({url}): {e}"))
}

impl IdpConfig {
    /// Fill the endpoints that were not set explicitly from a discovery
    /// document. Explicit settings always win. The document's `issuer` must
    /// match the configured one (ignoring a trailing slash) — OIDC Discovery §4.3.
    pub fn apply_discovery(&mut self, doc: &OidcDiscovery) -> Result<(), String> {
        if let Some(configured) = &self.issuer_url {
            if configured.trim_end_matches('/') != doc.issuer.trim_end_matches('/') {
                return Err(format!(
                    "discovery issuer mismatch: configured {configured}, document says {}",
                    doc.issuer
                ));
            }
        }
        // The exact `iss` value the IdP stamps into its tokens.
        self.issuer_url = Some(doc.issuer.clone());
        self.auth_url
            .get_or_insert_with(|| doc.authorization_endpoint.clone());
        self.token_url
            .get_or_insert_with(|| doc.token_endpoint.clone());
        if self.userinfo_url.is_none() {
            self.userinfo_url = doc.userinfo_endpoint.clone();
        }
        if self.jwks_url.is_none() {
            self.jwks_url = doc.jwks_uri.clone();
        }
        Ok(())
    }

    /// Whether the auth/token endpoints still need discovery (not set
    /// explicitly and not built into `provider`).
    pub fn needs_discovery(&self) -> bool {
        self.issuer_url.is_some()
            && (self.auth_url.is_none() || self.token_url.is_none() || self.userinfo_url.is_none())
    }

    /// Label for the login button.
    pub fn button_label(&self) -> String {
        if let Some(name) = self
            .display_name
            .as_deref()
            .filter(|s| !s.trim().is_empty())
        {
            return name.trim().to_string();
        }
        match self.provider.as_str() {
            "google" => "Google",
            "github" => "GitHub",
            "microsoft" => "Microsoft",
            "linkedin" => "LinkedIn",
            "apple" => "Apple",
            _ => "SSO",
        }
        .to_string()
    }
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
        self.authorization_url_impl(redirect_uri, state, nonce, code_challenge, None)
    }

    /// Like [`authorization_url_pkce`] but sets the OIDC `prompt` parameter
    /// (e.g. `select_account` to force the upstream IdP's account chooser, or
    /// `login` to force re-authentication). Used by the multi-account "add
    /// another account" flow.
    pub fn authorization_url_pkce_prompt(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: Option<&str>,
        prompt: Option<&str>,
    ) -> String {
        self.authorization_url_impl(redirect_uri, state, nonce, code_challenge, prompt)
    }

    fn authorization_url_impl(
        &self,
        redirect_uri: &str,
        state: &str,
        nonce: &str,
        code_challenge: Option<&str>,
        prompt: Option<&str>,
    ) -> String {
        let auth_url =
            self.config
                .auth_url
                .clone()
                .unwrap_or_else(|| match self.config.provider.as_str() {
                    "google" => "https://accounts.google.com/o/oauth2/v2/auth".into(),
                    "github" => "https://github.com/login/oauth/authorize".into(),
                    "microsoft" => {
                        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into()
                    }
                    "linkedin" => "https://www.linkedin.com/oauth/v2/authorization".into(),
                    "apple" => "https://appleid.apple.com/auth/authorize".into(),
                    _ => "".into(),
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

        let mut url =
            Url::parse(&auth_url).unwrap_or_else(|_| Url::parse("https://example.com").unwrap());
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
            if let Some(p) = prompt {
                pairs.append_pair("prompt", p);
            }
        }
        url.to_string()
    }

    /// Exchange authorization code for tokens.
    ///
    /// Back-compat shim — does not attach `code_verifier`. New callers should
    /// use [`IdpClient::exchange_code_pkce`] so the token exchange proves the
    /// original PKCE proof-of-possession.
    pub async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, String> {
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
        let token_url =
            self.config
                .token_url
                .clone()
                .unwrap_or_else(|| match self.config.provider.as_str() {
                    "google" => "https://oauth2.googleapis.com/token".into(),
                    "github" => "https://github.com/login/oauth/access_token".into(),
                    "microsoft" => {
                        "https://login.microsoftonline.com/common/oauth2/v2.0/token".into()
                    }
                    "linkedin" => "https://www.linkedin.com/oauth/v2/accessToken".into(),
                    "apple" => "https://appleid.apple.com/auth/token".into(),
                    _ => "".into(),
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

        let resp = self
            .http
            .post(&token_url)
            .form(&params)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("token exchange failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            // H5: the IdP error body can include client_id, redirect_uri
            // mismatch details, or token fragments — never surface it to the
            // browser. Log server-side and return a generic string.
            let body = resp.text().await.unwrap_or_default();
            tracing::warn!(status = %status, body = %body, "IdP token exchange error");
            return Err(format!("token exchange error: {}", status));
        }

        resp.json::<TokenResponse>()
            .await
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

        let resp = self
            .http
            .get(&userinfo_url)
            .bearer_auth(access_token)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| format!("userinfo failed: {}", e))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(format!("userinfo error: {}", resp.status()));
        }

        // GitHub has different field names
        if self.config.provider == "github" {
            let gh: GitHubUser = resp
                .json()
                .await
                .map_err(|e| format!("github user parse: {}", e))?;
            return Ok(IdpUserInfo {
                sub: gh.id.to_string(),
                email: gh.email,
                name: gh.name,
                picture: gh.avatar_url,
                email_verified: Some(true),
            });
        }

        resp.json::<IdpUserInfo>()
            .await
            .map_err(|e| format!("userinfo parse: {}", e))
    }

    pub fn provider(&self) -> &str {
        &self.config.provider
    }
    pub fn config(&self) -> &IdpConfig {
        &self.config
    }
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
        assert!(p
            .verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
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
            jwks_url: None,
            display_name: None,
        })
    }

    fn discovery_doc() -> OidcDiscovery {
        OidcDiscovery {
            issuer: "https://idp.example.com/realms/x".into(),
            authorization_endpoint: "https://idp.example.com/auth".into(),
            token_endpoint: "https://idp.example.com/token".into(),
            userinfo_endpoint: Some("https://idp.example.com/userinfo".into()),
            jwks_uri: Some("https://idp.example.com/certs".into()),
        }
    }

    fn generic_config() -> IdpConfig {
        IdpConfig {
            provider: "oidc".into(),
            client_id: "cid".into(),
            client_secret: "cs".into(),
            issuer_url: Some("https://idp.example.com/realms/x/".into()),
            auth_url: None,
            token_url: None,
            userinfo_url: None,
            scopes: vec![],
            jwks_url: None,
            display_name: None,
        }
    }

    #[test]
    fn discovery_fills_missing_endpoints() {
        let mut c = generic_config();
        assert!(c.needs_discovery());
        c.apply_discovery(&discovery_doc()).unwrap();
        assert_eq!(
            c.issuer_url.as_deref(),
            Some("https://idp.example.com/realms/x")
        );
        assert_eq!(c.auth_url.as_deref(), Some("https://idp.example.com/auth"));
        assert_eq!(
            c.token_url.as_deref(),
            Some("https://idp.example.com/token")
        );
        assert_eq!(
            c.userinfo_url.as_deref(),
            Some("https://idp.example.com/userinfo")
        );
        assert_eq!(c.jwks_url.as_deref(), Some("https://idp.example.com/certs"));
        assert!(!c.needs_discovery());
        let url = IdpClient::new(c).authorization_url("https://app/cb", "s", "n");
        assert!(url.starts_with("https://idp.example.com/auth?"), "{url}");
    }

    #[test]
    fn explicit_endpoints_win_over_discovery() {
        let mut c = generic_config();
        c.token_url = Some("https://override/token".into());
        c.apply_discovery(&discovery_doc()).unwrap();
        assert_eq!(c.token_url.as_deref(), Some("https://override/token"));
    }

    #[test]
    fn discovery_rejects_a_different_issuer() {
        let mut c = generic_config();
        c.issuer_url = Some("https://other.example.com".into());
        assert!(c.apply_discovery(&discovery_doc()).is_err());
    }

    #[test]
    fn google_without_issuer_needs_no_discovery() {
        // Production: IDP_PROVIDER=google and no IDP_ISSUER_URL.
        let c = test_client().config().clone();
        assert!(!c.needs_discovery());
        assert_eq!(c.button_label(), "Google");
    }

    #[test]
    fn button_label_prefers_display_name() {
        let mut c = generic_config();
        assert_eq!(c.button_label(), "SSO");
        c.display_name = Some("Keycloak".into());
        assert_eq!(c.button_label(), "Keycloak");
    }

    #[test]
    fn authorization_url_without_pkce_omits_challenge() {
        let url = test_client().authorization_url("https://app/cb", "s", "n");
        assert!(!url.contains("code_challenge"));
    }

    #[test]
    fn authorization_url_prompt_sets_select_account() {
        // Multi-account "add account" forces the upstream chooser.
        let url = test_client().authorization_url_pkce_prompt(
            "https://app/cb",
            "s",
            "n",
            Some("CHAL"),
            Some("select_account"),
        );
        assert!(
            url.contains("prompt=select_account"),
            "missing prompt: {url}"
        );
        // No prompt requested → parameter absent.
        let none = test_client().authorization_url_pkce("https://app/cb", "s", "n", Some("CHAL"));
        assert!(!none.contains("prompt="), "unexpected prompt: {none}");
    }

    #[test]
    fn authorization_url_with_pkce_includes_s256() {
        let url = test_client().authorization_url_pkce("https://app/cb", "s", "n", Some("CHAL"));
        assert!(url.contains("code_challenge=CHAL"));
        assert!(url.contains("code_challenge_method=S256"));
    }
}
