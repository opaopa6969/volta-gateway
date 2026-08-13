use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::record::DeviceGrantRecord;

/// Result of a device polling `/oauth/token` (RFC 8628 §3.5). Maps 1:1 to the
/// standard token-endpoint error responses the HTTP layer must return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevicePollOutcome {
    /// User approved — issue a token for this identity, then invalidate the grant.
    Approved {
        user_id: Uuid,
        tenant_id: Uuid,
        scope: Option<String>,
    },
    /// Still waiting for the user (`authorization_pending`).
    Pending,
    /// Polled faster than `interval` (`slow_down`).
    SlowDown,
    /// User declined (`access_denied`).
    Denied,
    /// Grant expired (`expired_token`).
    Expired,
    /// Unknown / already-consumed device_code (`invalid_grant`).
    NotFound,
}

/// Result of a user approving/denying at the verification page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceDecisionOutcome {
    /// Recorded (returns the client_id + scope for the confirmation screen).
    Ok {
        client_id: String,
        scope: Option<String>,
    },
    /// No pending grant for that user_code.
    NotFound,
    /// Grant existed but has expired.
    Expired,
    /// Already approved or denied.
    AlreadyResolved,
}

/// Persistence for OAuth 2.0 Device Authorization Grants (RFC 8628).
#[async_trait]
pub trait DeviceGrantStore: Send + Sync {
    /// Persist a freshly-issued (pending) grant.
    async fn create(&self, record: DeviceGrantRecord) -> Result<(), AuthError>;

    /// Look up a pending grant by its user_code (for the verification screen).
    async fn find_pending_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<Option<DeviceGrantRecord>, AuthError>;

    /// Record the user's decision. `approve=false` denies. On approve, records
    /// the identity the eventual token will represent.
    async fn decide(
        &self,
        user_code: &str,
        approve: bool,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<DeviceDecisionOutcome, AuthError>;

    /// Poll from the device. Enforces the `interval` (returns `SlowDown` when the
    /// device polls too fast) and single-use semantics on approval.
    async fn poll(&self, device_code_hash: &str) -> Result<DevicePollOutcome, AuthError>;

    /// Invalidate a grant after a token was successfully issued for it.
    async fn consume(&self, device_code_hash: &str) -> Result<(), AuthError>;

    /// Housekeeping: drop expired rows.
    async fn delete_expired(&self) -> Result<u64, AuthError>;
}
