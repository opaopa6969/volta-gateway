use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::record::{AuthzCodeRecord, OAuthClientRecord, RefreshTokenRecord};

/// Outcome of rotating a refresh token (RFC 6749 §10.4 + OAuth Security BCP
/// reuse detection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// Valid & now revoked — the caller mints a replacement in the same family.
    Rotated(RefreshTokenRecord),
    /// An already-revoked token was presented again → the whole family is
    /// compromised and has been revoked. Deny and force re-auth.
    Reused,
    Expired,
    NotFound,
}

#[async_trait]
pub trait OAuthClientStore: Send + Sync {
    async fn create_client(&self, record: OAuthClientRecord) -> Result<(), AuthError>;
    async fn find_client(&self, client_id: &str) -> Result<Option<OAuthClientRecord>, AuthError>;
    async fn list_clients(&self) -> Result<Vec<OAuthClientRecord>, AuthError>;
}

#[async_trait]
pub trait AuthzCodeStore: Send + Sync {
    async fn save_code(&self, record: AuthzCodeRecord) -> Result<(), AuthError>;
    /// Atomic single-use consume: returns the record only if it exists, is
    /// unexpired and not yet consumed. A second call returns `None`.
    async fn consume_code(&self, code_hash: &str) -> Result<Option<AuthzCodeRecord>, AuthError>;
}

#[async_trait]
pub trait RefreshTokenStore: Send + Sync {
    async fn save_refresh(&self, record: RefreshTokenRecord) -> Result<(), AuthError>;
    async fn rotate_refresh(&self, token_hash: &str) -> Result<RefreshOutcome, AuthError>;
    async fn revoke_refresh(&self, token_hash: &str) -> Result<(), AuthError>;
    async fn revoke_family(&self, family_id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
pub trait OAuthConsentStore: Send + Sync {
    /// True if the user has already consented to (at least) this scope for the client.
    async fn has_consent(&self, user_id: Uuid, client_id: &str, scope: &str) -> Result<bool, AuthError>;
    async fn grant_consent(&self, user_id: Uuid, client_id: &str, scope: &str) -> Result<(), AuthError>;
}
