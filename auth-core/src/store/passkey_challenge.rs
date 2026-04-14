use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::AuthError;

/// A pending WebAuthn challenge (backlog P1 #5).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct PasskeyChallengeRecord {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    /// bincode-serialised `PasskeyAuthentication` / `PasskeyRegistration`.
    pub state: Vec<u8>,
    /// `"auth"` | `"register"`.
    pub kind: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
pub trait PasskeyChallengeStore: Send + Sync {
    async fn save(&self, record: PasskeyChallengeRecord) -> Result<(), AuthError>;

    /// Atomic single-use consume. A duplicate call with the same id returns
    /// `None`; expired rows are also filtered here.
    async fn consume(&self, id: Uuid) -> Result<Option<PasskeyChallengeRecord>, AuthError>;

    async fn delete_expired(&self) -> Result<u64, AuthError>;
}
