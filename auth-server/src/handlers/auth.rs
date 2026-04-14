//! /auth/* handlers — verify, logout, refresh, switch-tenant.
//! 100% compatible with Java volta-auth-proxy.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};

use crate::auth_events::AuthEvent;
use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{extract_session_id, is_json_accept, set_session_cookie, clear_session_cookie};
use crate::state::AppState;
use volta_auth_core::store::{SessionStore, MembershipStore, TenantStore};

/// Publish a `LOGOUT` auth event for `/viz/auth/stream` (P1.2) and persist
/// it to `audit_logs` (P2 #10). Session lookup is best-effort — a missing
/// session still produces an event (SSE clients filter by event_type).
async fn publish_logout_event(state: &AppState, session_id: &str) {
    let mut ev = AuthEvent::now("LOGOUT").with_session(session_id);
    if let Ok(Some(s)) = SessionStore::find(&state.db, session_id).await {
        ev = ev.with_user(s.user_id).with_tenant(s.tenant_id);
    }
    state.auth_events.publish_and_audit(
        ev,
        &state.db,
        None,
        Some("SESSION".into()),
        Some(session_id.to_string()),
        None,
    ).await;
}

/// GET /auth/verify — ForwardAuth endpoint for gateway.
///
/// Order mirrors Java `AuthFlowHandler.verify` (`99a2769` + `4006ee7`):
///   1. Require forwarded headers from the gateway.
///   2. If a session cookie is present → resolve session:
///       a. session invalid/expired → redirect to /login
///       b. MFA pending → 302 to /mfa/challenge
///       c. OK → 200 + `X-Volta-*` headers
///   3. No session → local-network bypass: if the caller's IP is LAN/Tailscale,
///      return 200 anonymous with `X-Volta-Auth-Source: local-bypass` (P1.3).
///   4. No session + external IP → redirect to /login.
///
/// The bypass only fires when there is no session so that authenticated LAN
/// users still get their real user headers and MFA enforcement.
pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let forwarded_host = headers.get("x-forwarded-host").and_then(|v| v.to_str().ok());
    let forwarded_uri = headers.get("x-forwarded-uri").and_then(|v| v.to_str().ok());
    let forwarded_proto = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok()).unwrap_or("http");

    if forwarded_host.is_none() || forwarded_uri.is_none() {
        return ApiError::unauthorized("AUTHENTICATION_REQUIRED", "Missing forwarded headers").into_response();
    }

    let redirect_to_login = || {
        let return_to = format!("{}://{}{}", forwarded_proto, forwarded_host.unwrap(), forwarded_uri.unwrap());
        let location = format!("{}/login?return_to={}", state.base_url, urlencoding::encode(&return_to));
        let mut resp = Redirect::to(&location).into_response();
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        no_cache_headers(&mut resp);
        resp
    };

    // ── Session path ──────────────────────────────────────────
    if let Some(session_id) = extract_session_id(&jar) {
        let session = match SessionStore::find(&state.db, &session_id).await {
            Ok(Some(s)) => s,
            _ => return redirect_to_login(),
        };

        // P1.1 AUTH-010: MFA pending → send user to challenge (only if they are
        // not already navigating to the MFA page, to avoid redirect loops).
        if session.mfa_verified_at.is_none() {
            if let Some(uri) = forwarded_uri {
                let is_mfa_path = uri.starts_with("/mfa/") || uri.starts_with("/auth/mfa/");
                if !is_mfa_path {
                    let location = format!("{}/mfa/challenge", state.base_url);
                    let mut resp = Redirect::to(&location).into_response();
                    *resp.status_mut() = StatusCode::UNAUTHORIZED;
                    no_cache_headers(&mut resp);
                    return resp;
                }
            }
        }

        // Build volta headers
        let mut resp = StatusCode::OK.into_response();
        let h = resp.headers_mut();
        h.insert("x-volta-user-id", session.user_id.parse().unwrap());
        if let Some(ref email) = session.email {
            h.insert("x-volta-email", email.parse().unwrap());
        }
        h.insert("x-volta-tenant-id", session.tenant_id.parse().unwrap());
        if let Some(ref slug) = session.tenant_slug {
            h.insert("x-volta-tenant-slug", slug.parse().unwrap());
        }
        if !session.roles.is_empty() {
            h.insert("x-volta-roles", session.roles.join(",").parse().unwrap());
        }
        let display = session.display_name.as_deref().unwrap_or("");
        h.insert("x-volta-display-name", display.parse().unwrap());

        if let Ok(jwt) = state.jwt_issuer.issue(&volta_auth_core::jwt::VoltaClaims {
            sub: session.user_id.clone(),
            email: session.email.clone(),
            tenant_id: Some(session.tenant_id.clone()),
            tenant_slug: session.tenant_slug.clone(),
            roles: if session.roles.is_empty() { None } else { Some(session.roles.join(",")) },
            name: session.display_name.clone(),
            app_id: None,
            iat: None,
            exp: None,
        }) {
            h.insert("x-volta-jwt", jwt.parse().unwrap());
        }

        no_cache_headers(&mut resp);
        return resp;
    }

    // ── No session: local-network bypass (P1.3) ───────────────
    if state.local_bypass.matches_request(&headers, None) {
        let mut resp = StatusCode::OK.into_response();
        resp.headers_mut().insert("x-volta-auth-source", "local-bypass".parse().unwrap());
        no_cache_headers(&mut resp);
        return resp;
    }

    // ── External caller, no session → login ───────────────────
    redirect_to_login()
}

/// GET /auth/logout — browser logout with redirect.
pub async fn logout_get(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    if let Some(session_id) = extract_session_id(&jar) {
        publish_logout_event(&state, &session_id).await;
        let _ = SessionStore::revoke(&state.db, &session_id).await;
    }
    let mut resp = Redirect::to(&format!("{}/login", state.base_url)).into_response();
    clear_session_cookie(&mut resp, &state);
    no_cache_headers(&mut resp);
    resp
}

/// POST /auth/logout — API logout.
pub async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    if let Some(session_id) = extract_session_id(&jar) {
        publish_logout_event(&state, &session_id).await;
        let _ = SessionStore::revoke(&state.db, &session_id).await;
    }

    if is_json_accept(&headers) {
        let mut resp = Json(serde_json::json!({"ok": true})).into_response();
        clear_session_cookie(&mut resp, &state);
        no_cache_headers(&mut resp);
        resp
    } else {
        let mut resp = Redirect::to("/login").into_response();
        clear_session_cookie(&mut resp, &state);
        no_cache_headers(&mut resp);
        resp
    }
}

/// POST /auth/refresh — get fresh JWT.
pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let jwt = state.jwt_issuer.issue(&volta_auth_core::jwt::VoltaClaims {
        sub: session.user_id,
        email: session.email,
        tenant_id: Some(session.tenant_id),
        tenant_slug: session.tenant_slug,
        roles: if session.roles.is_empty() { None } else { Some(session.roles.join(",")) },
        name: session.display_name,
        app_id: None,
        iat: None,
        exp: None,
    }).map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"token": jwt})).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[derive(Deserialize)]
pub struct SwitchTenantRequest {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
}

/// POST /auth/switch-tenant — switch to a different tenant.
pub async fn switch_tenant(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<SwitchTenantRequest>,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    // Verify user has access to the target tenant
    let tenant_id: uuid::Uuid = body.tenant_id.parse()
        .map_err(|_| ApiError::bad_request("BAD_REQUEST", "invalid tenantId"))?;

    let user_id: uuid::Uuid = session.user_id.parse()
        .map_err(|_| ApiError::internal("invalid user_id in session"))?;
    let membership = MembershipStore::find(&state.db, user_id, tenant_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::forbidden("TENANT_ACCESS_DENIED", "Tenant access denied"))?;

    if !membership.is_active {
        return Err(ApiError::forbidden("TENANT_ACCESS_DENIED", "Tenant access denied"));
    }

    // Revoke old session, create new one with new tenant
    let _ = SessionStore::revoke(&state.db, &session_id).await;

    let tenant = TenantStore::find_by_id(&state.db, tenant_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "tenant not found"))?;

    let new_session_id = uuid::Uuid::new_v4().to_string();
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    SessionStore::create(&state.db, volta_auth_core::record::SessionRecord {
        session_id: new_session_id.clone(),
        user_id: session.user_id,
        tenant_id: body.tenant_id.clone(),
        return_to: None,
        created_at: now_epoch,
        last_active_at: now_epoch,
        expires_at: now_epoch + state.session_ttl_secs,
        invalidated_at: None,
        // #12: MFA verification does NOT carry over across tenants. If the new
        // tenant requires MFA, the user must re-verify in that tenant's context.
        // Previously we copied `session.mfa_verified_at`, which silently elevated
        // tenant B with MFA state obtained from tenant A.
        mfa_verified_at: None,
        ip_address: session.ip_address,
        user_agent: session.user_agent,
        csrf_token: None,
        email: session.email,
        tenant_slug: Some(tenant.slug),
        roles: vec![membership.role],
        display_name: session.display_name,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"ok": true, "tenantId": body.tenant_id})).into_response();
    set_session_cookie(&mut resp, &new_session_id, &state);
    no_cache_headers(&mut resp);
    Ok(resp)
}
