use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A registered OpenID Provider client (relying party). `client_secret_hash` is
/// `None` for public clients that authenticate with PKCE only.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct OAuthClientRecord {
    pub id: Uuid,
    pub client_id: String,
    pub client_secret_hash: Option<String>,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub is_confidential: bool,
    /// OIDC back-channel logout endpoint (server-to-server logout_token POST).
    pub backchannel_logout_uri: Option<String>,
    /// OIDC front-channel logout endpoint (loaded in an iframe from /end_session).
    pub frontchannel_logout_uri: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl OAuthClientRecord {
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }
    pub fn allows_grant(&self, grant: &str) -> bool {
        self.grant_types.iter().any(|g| g == grant)
    }
}

/// A single-use authorization code (PKCE). The raw code is never stored — only
/// its SHA-256 hash, with a short TTL and one-shot `consumed_at`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct AuthzCodeRecord {
    pub code_hash: String,
    pub client_id: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A refresh token in a rotation family. Presenting a `revoked_at` token again
/// (reuse) means the family is compromised and must be revoked wholesale.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct RefreshTokenRecord {
    pub token_hash: String,
    pub family_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}
