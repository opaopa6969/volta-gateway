use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::record::{NotificationJobRecord, NotificationLogRecord};

/// Persistence for the notification outbox (notification_jobs / notification_logs).
///
/// `enqueue` is idempotent on `correlation_id`: enqueuing the same correlation
/// twice (e.g. a retried user action) returns the existing job id instead of
/// creating a duplicate.
#[async_trait]
pub trait NotificationJobStore: Send + Sync {
    async fn enqueue(
        &self,
        channel: &str,
        recipient: &str,
        template_id: &str,
        payload: serde_json::Value,
        correlation_id: Option<&str>,
    ) -> Result<Uuid, AuthError>;

    /// Claim due, still-pending jobs (status='pending', next_attempt_at<=now).
    async fn claim_pending(&self, limit: i64) -> Result<Vec<NotificationJobRecord>, AuthError>;

    async fn mark_sent(&self, id: Uuid) -> Result<(), AuthError>;

    /// Reschedule with backoff (status stays 'pending').
    async fn mark_retry(&self, id: Uuid, attempt: i32, error: &str) -> Result<(), AuthError>;

    /// Give up (status='failed').
    async fn mark_failed(&self, id: Uuid, error: &str) -> Result<(), AuthError>;

    async fn log(&self, record: NotificationLogRecord) -> Result<(), AuthError>;
}
