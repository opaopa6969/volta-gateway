use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Persisted flow record — metadata for a tramli SM flow instance.
/// Context data stays in-memory; only metadata + summary are persisted.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct FlowRecord {
    pub id: Uuid,
    pub session_id: String,
    pub flow_type: String,
    pub current_state: String,
    pub guard_failure_count: i32,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub exit_state: Option<String>,
    pub summary: Option<serde_json::Value>,
}

/// Persisted flow transition record — audit log of state transitions.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct FlowTransitionRecord {
    pub id: i64,
    pub flow_id: Uuid,
    pub from_state: Option<String>,
    pub to_state: String,
    pub trigger: String,
    pub error_detail: Option<String>,
    pub created_at: DateTime<Utc>,
}
