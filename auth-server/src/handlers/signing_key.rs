//! Signing key management handlers — rotation, revocation, JWKS.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;

use crate::error::ApiError;
use crate::helpers::require_admin;
use crate::state::AppState;
use volta_auth_core::store::SigningKeyStore;

/// GET /api/v1/admin/keys — list signing keys (admin).
pub async fn list_keys(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let _ = require_admin(&state, &jar).await?;
    let keys = SigningKeyStore::list(&state.db)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let items: Vec<serde_json::Value> = keys
        .iter()
        .map(|k| {
            serde_json::json!({
                "kid": k.kid,
                "status": k.status,
                "created_at": k.created_at.to_rfc3339(),
                "rotated_at": k.rotated_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    Ok(Json(items).into_response())
}

/// POST /api/v1/admin/keys/rotate — rotate signing key.
pub async fn rotate_key(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let _ = require_admin(&state, &jar).await?;
    // Load current active key
    let current = SigningKeyStore::load_active(&state.db)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    // Generate a new RSA (RS256) key pair — the OP publishes its public half at
    // /.well-known/jwks.json (Phase 3a). The previous key is retired (not
    // revoked), so tokens it signed still verify until they expire.
    let new_kid = uuid::Uuid::new_v4().to_string();
    let (public_pem, private_pem) =
        crate::op_keys::generate_rsa_pem().map_err(|e| ApiError::internal(&e))?;

    match current {
        Some(old) => {
            SigningKeyStore::rotate(&state.db, &old.kid, &new_kid, &public_pem, &private_pem)
                .await
                .map_err(|e| ApiError::internal(&e.to_string()))?;
        }
        None => {
            SigningKeyStore::save(&state.db, &new_kid, &public_pem, &private_pem)
                .await
                .map_err(|e| ApiError::internal(&e.to_string()))?;
        }
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "kid": new_kid,
    }))
    .into_response())
}

/// POST /api/v1/admin/keys/{kid}/revoke — revoke a signing key.
pub async fn revoke_key(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(kid): Path<String>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&state, &jar).await?;
    SigningKeyStore::revoke(&state.db, &kid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})).into_response())
}
