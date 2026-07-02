use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;

/// Silent per-user device memory for risk-based auth (Phase 4c). A device the
/// user has logged in from before is lower risk; a brand-new one is a signal.
#[async_trait]
pub trait RiskDeviceStore: Send + Sync {
    /// Record that `user_id` logged in from the device identified by
    /// `device_hash`, and report whether it was **already known** (`true`) or
    /// **new** (`false`). Idempotent — refreshes `last_seen`.
    async fn check_and_record(&self, user_id: Uuid, device_hash: &str) -> Result<bool, AuthError>;
}

/// Risk step-up markers (Phase 4c): a session flagged as needing an extra factor.
#[async_trait]
pub trait SessionStepUpStore: Send + Sync {
    /// Flag a session as requiring step-up. Idempotent.
    async fn mark(&self, session_id: &str) -> Result<(), AuthError>;
    /// Whether the session still needs step-up.
    async fn is_required(&self, session_id: &str) -> Result<bool, AuthError>;
}
