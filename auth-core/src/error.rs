/// Auth error types.
#[derive(Debug, Clone)]
pub enum AuthError {
    SessionNotFound,
    SessionExpired,
    SessionRevoked,
    PolicyDenied(String),
    MfaRequired,
    ReauthRequired,
    NotFound(String),
    Conflict(String),
    StoreError(String),
    Internal(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::SessionNotFound => write!(f, "session not found"),
            AuthError::SessionExpired => write!(f, "session expired"),
            AuthError::SessionRevoked => write!(f, "session revoked"),
            AuthError::PolicyDenied(r) => write!(f, "policy denied: {}", r),
            AuthError::MfaRequired => write!(f, "MFA required"),
            AuthError::ReauthRequired => write!(f, "re-authentication required"),
            AuthError::NotFound(e) => write!(f, "not found: {}", e),
            AuthError::Conflict(e) => write!(f, "conflict: {}", e),
            AuthError::StoreError(e) => write!(f, "store error: {}", e),
            AuthError::Internal(e) => write!(f, "internal: {}", e),
        }
    }
}

#[cfg(feature = "postgres")]
impl From<sqlx::Error> for AuthError {
    fn from(e: sqlx::Error) -> Self {
        match &e {
            sqlx::Error::RowNotFound => AuthError::NotFound("row not found".into()),
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                AuthError::Conflict(db_err.message().to_string())
            }
            _ => AuthError::StoreError(e.to_string()),
        }
    }
}
