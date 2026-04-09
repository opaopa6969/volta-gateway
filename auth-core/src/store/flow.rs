use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::FlowRecord;

/// Flow persistence trait — persists tramli SM flow metadata to a database.
///
/// tramli's `FlowStore<S>` is in-process/sync only; this trait provides
/// async DB persistence alongside the in-memory engine.
#[async_trait]
pub trait FlowPersistence: Send + Sync {
    /// Create a new flow record.
    async fn create(&self, record: FlowRecord) -> Result<(), AuthError>;

    /// Find a flow by ID.
    async fn find(&self, id: Uuid) -> Result<Option<FlowRecord>, AuthError>;

    /// Update flow state + bump version (optimistic locking).
    async fn update_state(&self, id: Uuid, state: &str, version: i32) -> Result<(), AuthError>;

    /// Mark a flow as completed.
    async fn complete(
        &self,
        id: Uuid,
        exit_state: &str,
        summary: Option<serde_json::Value>,
    ) -> Result<(), AuthError>;

    /// Record a state transition (audit log).
    async fn record_transition(
        &self,
        flow_id: Uuid,
        from: Option<&str>,
        to: &str,
        trigger: &str,
        error: Option<&str>,
    ) -> Result<(), AuthError>;

    /// Find active (non-completed, non-expired) flows for a session.
    async fn find_active_by_session(&self, session_id: &str) -> Result<Vec<FlowRecord>, AuthError>;

    /// Delete expired flows. Returns count of deleted rows.
    async fn cleanup_expired(&self) -> Result<usize, AuthError>;
}
