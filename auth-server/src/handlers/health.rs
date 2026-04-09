//! Health check + JWKS endpoints.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::AppState;

/// GET /healthz
pub async fn healthz(State(_state): State<AppState>) -> Response {
    Json(serde_json::json!({"status": "ok"})).into_response()
}

/// GET /.well-known/jwks.json — JSON Web Key Set.
/// For HS256: returns empty keys array (shared secret, not public).
/// For RS256: would return public key. (TODO: signing key rotation)
pub async fn jwks(State(_state): State<AppState>) -> Response {
    Json(serde_json::json!({"keys": []})).into_response()
}
