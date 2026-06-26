use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A hashed, expiring, single-use email verification token.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct EmailVerificationTokenRecord {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub flow_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub attempt_count: i32,
    pub resend_count: i32,
    pub last_sent_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
