/// Auth error types.
#[derive(Debug, Clone)]
pub enum AuthError {
    SessionNotFound,
    SessionExpired,
    SessionRevoked,
    PolicyDenied(String),
    MfaRequired,
    ReauthRequired,
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
            AuthError::Internal(e) => write!(f, "internal: {}", e),
        }
    }
}
