use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::{MfaRecord, RecoveryCodeRecord, MagicLinkRecord, SigningKeyRecord};

/// MFA store — TOTP secret management.
#[async_trait]
pub trait MfaStore: Send + Sync {
    async fn upsert(&self, user_id: Uuid, mfa_type: &str, secret: &str) -> Result<(), AuthError>;
    async fn find(&self, user_id: Uuid, mfa_type: &str) -> Result<Option<MfaRecord>, AuthError>;
    async fn has_active(&self, user_id: Uuid) -> Result<bool, AuthError>;
    async fn deactivate(&self, user_id: Uuid, mfa_type: &str) -> Result<(), AuthError>;
}

/// Recovery code store.
#[async_trait]
pub trait RecoveryCodeStore: Send + Sync {
    async fn replace_all(&self, user_id: Uuid, code_hashes: &[String]) -> Result<(), AuthError>;
    async fn consume(&self, user_id: Uuid, code_hash: &str) -> Result<bool, AuthError>;
    async fn count_unused(&self, user_id: Uuid) -> Result<usize, AuthError>;
    async fn delete_all(&self, user_id: Uuid) -> Result<(), AuthError>;
}

/// Magic link store.
#[async_trait]
pub trait MagicLinkStore: Send + Sync {
    async fn create(&self, email: &str, token: &str, ttl_minutes: i64) -> Result<(), AuthError>;
    async fn consume(&self, token: &str) -> Result<Option<MagicLinkRecord>, AuthError>;
}

/// Signing key store.
#[async_trait]
pub trait SigningKeyStore: Send + Sync {
    async fn save(&self, kid: &str, public_pem: &str, private_pem: &str) -> Result<(), AuthError>;
    async fn load_active(&self) -> Result<Option<SigningKeyRecord>, AuthError>;
    async fn list(&self) -> Result<Vec<SigningKeyRecord>, AuthError>;
    async fn rotate(&self, old_kid: &str, new_kid: &str, public_pem: &str, private_pem: &str) -> Result<(), AuthError>;
    async fn revoke(&self, kid: &str) -> Result<(), AuthError>;
}
