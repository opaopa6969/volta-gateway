use std::sync::Arc;
use volta_auth_core::idp::IdpClient;
use volta_auth_core::jwt::{JwtIssuer, JwtVerifier};
use volta_auth_core::store::pg::PgStore;

/// Shared application state for all handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgStore,
    pub idp: Arc<IdpClient>,
    pub jwt_issuer: JwtIssuer,
    pub jwt_verifier: JwtVerifier,
    /// Cookie domain (e.g. ".example.com"). Empty = browser default.
    pub cookie_domain: String,
    /// Session TTL in seconds (default 28800 = 8h).
    pub session_ttl_secs: u64,
    /// Force Secure flag on cookies even without HTTPS.
    pub force_secure_cookie: bool,
    /// Base URL for redirects (e.g. "https://auth.example.com").
    pub base_url: String,
    /// HMAC key for signing OIDC state parameters.
    pub state_signing_key: Vec<u8>,
}
