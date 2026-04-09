//! Magic Link handlers — passwordless email auth.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::set_session_cookie;
use crate::state::AppState;
use volta_auth_core::store::{MagicLinkStore, UserStore, TenantStore, MembershipStore, SessionStore};

#[derive(Deserialize)]
pub struct SendRequest {
    pub email: String,
}

/// POST /auth/magic-link/send — generate magic link token.
pub async fn send(
    State(state): State<AppState>,
    Json(body): Json<SendRequest>,
) -> Result<Response, ApiError> {
    let token = uuid::Uuid::new_v4().to_string().replace('-', "");

    MagicLinkStore::create(&state.db, &body.email, &token, 15).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    // In production: send email via EmailSender trait.
    // For now: return token in response (dev mode).
    let link = format!("{}/auth/magic-link/verify?token={}", state.base_url, token);

    let mut resp = Json(serde_json::json!({
        "ok": true,
        "message": "Magic link sent",
        "link": link, // dev only — remove in production
    })).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[derive(Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

/// GET /auth/magic-link/verify — consume token and create session.
pub async fn verify(
    State(state): State<AppState>,
    Query(q): Query<VerifyQuery>,
) -> Result<Response, ApiError> {
    let record = MagicLinkStore::consume(&state.db, &q.token).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("INVALID_TOKEN", "Invalid or expired magic link"))?;

    // Find or create user
    let user = match UserStore::find_by_email(&state.db, &record.email).await
        .map_err(|e| ApiError::internal(&e.to_string()))? {
        Some(u) => u,
        None => {
            // Auto-create user from magic link email
            UserStore::upsert(&state.db, volta_auth_core::record::UserRecord {
                id: uuid::Uuid::new_v4(),
                email: record.email.clone(),
                display_name: Some(record.email.split('@').next().unwrap_or("user").to_string()),
                google_sub: None,
                created_at: chrono::Utc::now(),
                is_active: true,
                locale: None,
                deleted_at: None,
            }).await.map_err(|e| ApiError::internal(&e.to_string()))?
        }
    };

    // Resolve tenant
    let tenants = TenantStore::find_by_user(&state.db, user.id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let (tenant_id, tenant_slug, roles) = if let Some(t) = tenants.first() {
        let m = MembershipStore::find(&state.db, user.id, t.id).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        let role = m.map(|m| m.role).unwrap_or_else(|| "MEMBER".into());
        (t.id.to_string(), Some(t.slug.clone()), vec![role])
    } else {
        let slug = record.email.split('@').next().unwrap_or("user").to_string();
        let t = TenantStore::create_personal(&state.db, user.id, &user.display_name.clone().unwrap_or(slug.clone()), &slug).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        (t.id.to_string(), Some(t.slug), vec!["OWNER".into()])
    };

    // Create session
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    SessionStore::create(&state.db, volta_auth_core::record::SessionRecord {
        session_id: session_id.clone(),
        user_id: user.id.to_string(),
        tenant_id,
        return_to: None,
        created_at: now,
        last_active_at: now,
        expires_at: now + state.session_ttl_secs,
        invalidated_at: None,
        mfa_verified_at: None,
        ip_address: None,
        user_agent: None,
        csrf_token: None,
        email: Some(record.email),
        tenant_slug,
        roles,
        display_name: user.display_name,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = axum::response::Redirect::to(&format!("{}/", state.base_url)).into_response();
    set_session_cookie(&mut resp, &session_id, &state);
    no_cache_headers(&mut resp);
    Ok(resp)
}
