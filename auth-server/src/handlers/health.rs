//! Health check + JWKS endpoints.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::AppState;
use volta_auth_core::store::SigningKeyStore;

/// GET /healthz
pub async fn healthz(State(_state): State<AppState>) -> Response {
    Json(serde_json::json!({"status": "ok"})).into_response()
}

/// GET /.well-known/jwks.json — JSON Web Key Set (Phase 3a).
///
/// Publishes the OP RS256 **public** keys so relying parties can verify
/// id/access tokens. Retired keys are kept (tokens they signed may still be in
/// flight); revoked keys are dropped. Legacy HS256 placeholder rows (not RSA
/// PEM) are silently skipped. The internal session JWT stays HS256 (shared
/// secret) and never appears here.
pub async fn jwks(State(state): State<AppState>) -> Response {
    let keys: Vec<serde_json::Value> = match SigningKeyStore::list(&state.db).await {
        Ok(rows) => rows
            .into_iter()
            .filter(|k| k.status != "revoked")
            .filter_map(|k| crate::op_keys::rsa_public_pem_to_jwk(&k.public_key, &k.kid))
            .collect(),
        Err(_) => Vec::new(),
    };
    Json(serde_json::json!({ "keys": keys })).into_response()
}
