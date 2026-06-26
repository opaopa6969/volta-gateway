use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A login OTP challenge (Email/SMS/LINE). The OTP itself is never stored — only
/// its hash, with expiry + bounded attempts.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct LoginChallengeRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub kind: String,
    pub code_hash: String,
    pub destination: String,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub created_at: DateTime<Utc>,
}
