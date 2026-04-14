use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::AuthError;
use crate::record::OidcFlowRecord;

/// DB-backed storage for in-flight OIDC flows (Backlog P0 #1).
///
/// Provides atomic single-use semantics so an attacker cannot replay a
/// leaked `?state=…` value: `consume` performs `DELETE … RETURNING …` so
/// the second call with the same state returns `None` even under
/// concurrent callbacks.
#[async_trait]
pub trait OidcFlowStore: Send + Sync {
    /// Persist a freshly-minted flow.
    async fn save(&self, record: OidcFlowRecord) -> Result<(), AuthError>;

    /// Atomically fetch + delete the flow keyed by `state`.
    ///
    /// Returns `None` when the state is unknown, already consumed, or
    /// expired. Callers treat `None` as "reject callback".
    async fn consume(&self, state: &str) -> Result<Option<OidcFlowRecord>, AuthError>;

    /// Housekeeping: drop all rows with `expires_at <= now()`.
    async fn delete_expired(&self) -> Result<u64, AuthError>;
}
