use std::sync::Arc;
use volta_auth_core::idp::IdpClient;
use volta_auth_core::jwt::{JwtIssuer, JwtVerifier};
use volta_auth_core::store::pg::PgStore;

use crate::auth_events::AuthEventBus;
use crate::local_bypass::LocalNetworkBypass;

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
    /// Local-network bypass for `/auth/verify` (P1.3, Java `5f23f88`+`4006ee7`).
    pub local_bypass: Arc<LocalNetworkBypass>,
    /// Auth event bus for `/viz/auth/stream` (P1.2, Java `9b4fe2c`).
    pub auth_events: AuthEventBus,
}
