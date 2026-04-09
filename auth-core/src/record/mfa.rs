use chrono::{DateTime, Utc};
use uuid::Uuid;

/// MFA configuration record (TOTP secret per user).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct MfaRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    #[cfg_attr(feature = "postgres", sqlx(rename = "type"))]
    pub mfa_type: String,
    pub secret: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// MFA recovery code record.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct RecoveryCodeRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Magic link record.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct MagicLinkRecord {
    pub id: Uuid,
    pub email: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Signing key record.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct SigningKeyRecord {
    pub kid: String,
    pub public_key: String,
    pub private_key: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}
