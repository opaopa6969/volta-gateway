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
