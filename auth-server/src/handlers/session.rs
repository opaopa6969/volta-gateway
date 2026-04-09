//! Session management handlers.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::extract_session_id;
use crate::state::AppState;
use volta_auth_core::store::SessionStore;

/// GET /api/me/sessions — list user's active sessions.
pub async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let sessions = SessionStore::list_by_user(&state.db, &session.user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let items: Vec<serde_json::Value> = sessions.iter().map(|s| {
        serde_json::json!({
            "session_id": s.session_id,
            "ip_address": s.ip_address,
            "user_agent": s.user_agent,
            "created_at": s.created_at,
            "last_active_at": s.last_active_at,
            "current": s.session_id == session_id,
        })
    }).collect();

    Ok(Json(items).into_response())
}

/// DELETE /api/me/sessions/{id} — revoke a specific session.
pub async fn revoke_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(target_id): Path<String>,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    // Verify caller is authenticated
    let _session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    SessionStore::revoke(&state.db, &target_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

/// DELETE /api/me/sessions — revoke all sessions for user.
pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let count = SessionStore::revoke_all_for_user(&state.db, &session.user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"ok": true, "revoked": count})).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}
