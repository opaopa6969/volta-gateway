use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Tenant record — mirrors Java TenantRecord + DB columns.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct TenantRecord {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub email_domain: Option<String>,
    pub auto_join: bool,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub plan: Option<String>,
    pub max_members: Option<i32>,
    pub is_active: bool,
    pub mfa_required: bool,
    pub mfa_grace_until: Option<DateTime<Utc>>,
}
