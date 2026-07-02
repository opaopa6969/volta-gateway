use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A pending OAuth 2.0 Device Authorization Grant (RFC 8628).
///
/// The `device_code` handed to the polling device is never stored in the clear —
/// only its SHA-256 hash. The short, human-typeable `user_code` is what the user
/// enters (or scans via `verification_uri_complete`) on a second device to
/// approve. `status` walks pending → approved/denied, and any row past
/// `expires_at` is treated as expired regardless of stored status.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct DeviceGrantRecord {
    pub id: Uuid,
    /// SHA-256 hex of the `device_code` (raw code never persisted).
    pub device_code_hash: String,
    /// Human-typeable code shown on the device, e.g. `WDJB-MJHT`.
    pub user_code: String,
    /// OAuth client that requested the grant (public/native client id).
    pub client_id: String,
    /// Requested scope (space-delimited), if any.
    pub scope: Option<String>,
    /// `pending` | `approved` | `denied` | `expired`.
    pub status: String,
    /// Set once a user approves — the identity the issued token represents.
    pub user_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    /// Minimum seconds the device must wait between `/oauth/token` polls.
    pub interval_secs: i32,
    /// Last time the device polled (for `slow_down` enforcement).
    pub last_polled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
