use async_trait::async_trait;
use uuid::Uuid;

use crate::error::AuthError;

/// Result of verifying a login OTP. Failure variants are kept distinct so the
/// caller can lock / rate-limit, but the HTTP layer should return a *generic*
/// failure to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeVerifyOutcome {
    Verified,
    WrongCode { attempts_remaining: i32 },
    Expired,
    TooManyAttempts,
    NotFound,
}

/// Persistence for login OTP challenges.
#[async_trait]
pub trait LoginChallengeStore: Send + Sync {
    /// Issue a challenge (invalidating any prior active one for the user).
    /// `code_hash` is the SHA-256 of the OTP; the raw OTP is never stored.
    async fn issue(
        &self,
        user_id: Uuid,
        kind: &str,
        code_hash: &str,
        destination: &str,
        ttl_minutes: i64,
        max_attempts: i32,
    ) -> Result<Uuid, AuthError>;

    /// Verify a submitted code against the user's active challenge. Increments
    /// the attempt counter on a wrong code; marks consumed on success.
    async fn verify(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<ChallengeVerifyOutcome, AuthError>;
}
