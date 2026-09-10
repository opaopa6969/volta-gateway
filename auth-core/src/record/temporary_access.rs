use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Server-authoritative, revocable temporary access grant.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct TemporaryAccessGrantRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub token_hash: String,
    pub subject: String,
    pub role: String,
    pub domains: Vec<String>,
    pub starts_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl TemporaryAccessGrantRecord {
    pub fn is_active_for(&self, host: &str, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none()
            && self.starts_at <= now
            && now < self.expires_at
            && self.domains.iter().any(|domain| domain == host)
    }
}
