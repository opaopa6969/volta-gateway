use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::record::{AuthzCodeRecord, OAuthClientRecord, RefreshTokenRecord, UserIdentityRecord};

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

/// Account linking — a user's federated identities.
#[async_trait]
pub trait UserIdentityStore: Send + Sync {
    /// Resolve an identity by its IdP (provider, subject).
    async fn find_by_subject(&self, provider: &str, subject: &str) -> Result<Option<UserIdentityRecord>, AuthError>;
    /// List all identities linked to a user.
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<UserIdentityRecord>, AuthError>;
    /// Link an identity (idempotent on (provider, subject)).
    async fn link(&self, record: UserIdentityRecord) -> Result<(), AuthError>;
    /// Unlink by id, scoped to the owning user. Returns true if a row was removed.
    async fn unlink(&self, user_id: Uuid, id: Uuid) -> Result<bool, AuthError>;
    async fn count_by_user(&self, user_id: Uuid) -> Result<i64, AuthError>;
}

#[async_trait]
pub trait OAuthConsentStore: Send + Sync {
    /// True if the user has already consented to (at least) this scope for the client.
    async fn has_consent(&self, user_id: Uuid, client_id: &str, scope: &str) -> Result<bool, AuthError>;
    async fn grant_consent(&self, user_id: Uuid, client_id: &str, scope: &str) -> Result<(), AuthError>;
}
