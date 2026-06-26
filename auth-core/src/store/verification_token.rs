use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;
use crate::record::EmailVerificationTokenRecord;

/// Persistence for email verification tokens. The caller hashes the raw token
/// (see [`crate::crypto::sha256_hex`] / [`crate::crypto::random_token_hex`])
/// and only ever passes the hash here — the raw token is never stored.
#[async_trait]
pub trait EmailVerificationTokenStore: Send + Sync {
    /// Create a token row. `ttl_minutes` sets `expires_at = now() + ttl`.
    async fn issue(
        &self,
        email: &str,
        token_hash: &str,
        ttl_minutes: i64,
        flow_id: Option<Uuid>,
    ) -> Result<Uuid, AuthError>;

    /// Atomically consume: if a matching, unused, unexpired token exists, mark
    /// it used and return it. Reuse / expired / unknown all yield `None`.
    async fn consume(
        &self,
        token_hash: &str,
    ) -> Result<Option<EmailVerificationTokenRecord>, AuthError>;

    /// Resend throttle. Bumps `resend_count` + `last_sent_at` on the newest
    /// pending token for `email` and returns `true` iff the previous send was
    /// more than `min_interval_secs` ago (or never). Returns `false` when
    /// throttled or when there is no pending token.
    async fn try_mark_resent(
        &self,
        email: &str,
        min_interval_secs: i64,
    ) -> Result<bool, AuthError>;

    /// Invalidate (mark used) all pending tokens for an email. Call before
    /// issuing a fresh one so only one token is ever live per address.
    async fn invalidate_pending(&self, email: &str) -> Result<u64, AuthError>;
}
