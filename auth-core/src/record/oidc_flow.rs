use chrono::{DateTime, Utc};
use uuid::Uuid;

/// In-flight OIDC flow record — stored between `/login?start=1` and `/callback`.
///
/// The `code_verifier_encrypted` column holds a base64-encoded ciphertext
/// produced by [`crate::crypto::KeyCipher`]; handlers decrypt just before the
/// token exchange.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct OidcFlowRecord {
    pub id: Uuid,
    pub state: String,
    pub nonce: String,
    pub code_verifier_encrypted: String,
    pub return_to: Option<String>,
    pub invite_code: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
