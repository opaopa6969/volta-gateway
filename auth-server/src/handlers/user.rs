//! User profile handlers.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;

use crate::error::ApiError;
use crate::helpers::require_session;
use crate::state::AppState;
use volta_auth_core::store::{MembershipStore, TenantStore, UserStore};

async fn active_user(
    state: &AppState,
    jar: &CookieJar,
) -> Result<volta_auth_core::record::UserRecord, ApiError> {
    let session = require_session(state, jar).await?;
    let user_id: uuid::Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("invalid user_id"))?;
    UserStore::find_by_id(&state.db, user_id)
        .await
        .map_err(ApiError::from)?
        .filter(|user| user.is_active && user.deleted_at.is_none())
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "account is unavailable"))
}

/// GET /api/v1/users/me — authenticated user profile.
pub async fn me(State(state): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let user = active_user(&state, &jar).await?;
    Ok(Json(serde_json::json!({
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "locale": user.locale,
        "created_at": user.created_at.to_rfc3339(),
    }))
    .into_response())
}

/// GET /api/v1/users/me/tenants — user's tenants with roles.
pub async fn me_tenants(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let user_id = active_user(&state, &jar).await?.id;
    let tenants = TenantStore::find_by_user(&state.db, user_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut items = Vec::new();
    for t in &tenants {
        let Some(membership) = MembershipStore::find(&state.db, user_id, t.id)
            .await
            .map_err(ApiError::from)?
            .filter(|membership| membership.is_active)
        else {
            continue;
        };
        items.push(serde_json::json!({
            "id": t.id,
            "name": t.name,
            "slug": t.slug,
            "role": membership.role,
        }));
    }

    Ok(Json(items).into_response())
}
