use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// API error — 100% compatible with Java volta-auth-proxy error format.
///
/// JSON: `{"error": {"code": "...", "message": "..."}}`
#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Serialize)]
struct ErrorInner {
    code: String,
    message: String,
}

impl ApiError {
    pub fn bad_request(code: &str, message: &str) -> Self {
        Self { status: StatusCode::BAD_REQUEST, code: code.into(), message: message.into() }
    }

    pub fn unauthorized(code: &str, message: &str) -> Self {
        Self { status: StatusCode::UNAUTHORIZED, code: code.into(), message: message.into() }
    }

    pub fn forbidden(code: &str, message: &str) -> Self {
        Self { status: StatusCode::FORBIDDEN, code: code.into(), message: message.into() }
    }

    pub fn internal(message: &str) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, code: "INTERNAL_ERROR".into(), message: message.into() }
    }

    pub fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self { status, code: code.into(), message: message.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: ErrorInner {
                code: self.code,
                message: self.message,
            },
        };
        let mut resp = (self.status, axum::Json(body)).into_response();
        // Java compat: always set cache headers
        let headers = resp.headers_mut();
        headers.insert("cache-control", "no-store, no-cache, must-revalidate, private".parse().unwrap());
        headers.insert("pragma", "no-cache".parse().unwrap());
        resp
    }
}

impl From<volta_auth_core::error::AuthError> for ApiError {
    fn from(e: volta_auth_core::error::AuthError) -> Self {
        use volta_auth_core::error::AuthError;
        match e {
            AuthError::SessionNotFound | AuthError::SessionExpired => {
                ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。")
            }
            AuthError::SessionRevoked => {
                ApiError::unauthorized("SESSION_EXPIRED", "セッションが無効化されました。")
            }
            AuthError::PolicyDenied(msg) => {
                ApiError::forbidden("TENANT_ACCESS_DENIED", &msg)
            }
            AuthError::MfaRequired => {
                ApiError::unauthorized("MFA_REQUIRED", "MFA verification required")
            }
            AuthError::NotFound(msg) => {
                ApiError::bad_request("NOT_FOUND", &msg)
            }
            AuthError::Conflict(msg) => {
                ApiError::bad_request("CONFLICT", &msg)
            }
            _ => ApiError::internal(&e.to_string()),
        }
    }
}

/// Append no-cache headers to a response (Java compat).
pub fn no_cache_headers(resp: &mut Response) {
    let headers = resp.headers_mut();
    headers.insert("cache-control", "no-store, no-cache, must-revalidate, private".parse().unwrap());
    headers.insert("pragma", "no-cache".parse().unwrap());
}
