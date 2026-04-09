//! User profile handlers.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;

use crate::error::ApiError;
use crate::helpers::extract_session_id;
use crate::state::AppState;
use volta_auth_core::store::{SessionStore, UserStore, TenantStore, MembershipStore};

/// GET /api/v1/users/me — authenticated user profile.
pub async fn me(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let user_id: uuid::Uuid = session.user_id.parse()
        .map_err(|_| ApiError::internal("invalid user_id"))?;

    let user = UserStore::find_by_id(&state.db, user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::internal("user not found"))?;

    Ok(Json(serde_json::json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "locale": user.locale,
        "created_at": user.created_at.to_rfc3339(),
    })).into_response())
}

/// GET /api/v1/users/me/tenants — user's tenants with roles.
pub async fn me_tenants(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let user_id: uuid::Uuid = session.user_id.parse()
        .map_err(|_| ApiError::internal("invalid user_id"))?;

    let tenants = TenantStore::find_by_user(&state.db, user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut items = Vec::new();
    for t in &tenants {
        let membership = MembershipStore::find(&state.db, user_id, t.id).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        let role = membership.map(|m| m.role).unwrap_or_else(|| "MEMBER".into());
        items.push(serde_json::json!({
            "id": t.id,
            "name": t.name,
            "slug": t.slug,
            "role": role,
        }));
    }

    Ok(Json(items).into_response())
}
