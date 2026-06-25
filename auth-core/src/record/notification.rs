use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A queued notification (notification_jobs). Enqueued in the same tx as a flow
/// state transition; delivered by a worker after commit.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct NotificationJobRecord {
    pub id: Uuid,
    pub channel: String,
    pub recipient: String,
    pub template_id: String,
    pub payload: serde_json::Value,
    pub correlation_id: Option<String>,
    pub status: String,
    pub attempt_count: i32,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// A delivery attempt result (notification_logs).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct NotificationLogRecord {
    pub id: i64,
    pub job_id: Option<Uuid>,
    pub channel: String,
    pub provider: String,
    pub recipient: String,
    pub template_id: String,
    pub outcome: String,
    pub message_id: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}
