use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Invitation record — mirrors Java InvitationRecord + DB columns.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct InvitationRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub code: String,
    pub email: Option<String>,
    pub role: String,
    pub max_uses: i32,
    pub used_count: i32,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl InvitationRecord {
    pub fn is_usable_at(&self, now: DateTime<Utc>) -> bool {
        self.used_count < self.max_uses && self.expires_at > now
    }
}
