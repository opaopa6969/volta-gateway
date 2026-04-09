use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Membership record — mirrors Java MembershipRecord + DB columns.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct MembershipRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub invited_by: Option<Uuid>,
    pub is_active: bool,
}
