use chrono::{DateTime, Utc};
use uuid::Uuid;

/// User record — mirrors Java UserRecord + DB columns.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub google_sub: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
    pub locale: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
}
