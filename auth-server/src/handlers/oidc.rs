//! OIDC login + callback handlers.
//! 100% compatible with Java OidcFlowRouter.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{is_json_accept, set_session_cookie, sign_state, verify_state};
use crate::state::AppState;

use volta_auth_core::store::{SessionStore, UserStore, TenantStore, MembershipStore};

#[derive(Deserialize)]
pub struct LoginQuery {
    pub start: Option<String>,
    pub return_to: Option<String>,
    pub invite: Option<String>,
}

/// GET /login — show login page or start OIDC redirect.
pub async fn login(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
) -> Response {
    let return_to = q.return_to.unwrap_or_else(|| format!("{}/", state.base_url));

    // If start=1, redirect to IdP immediately
    if q.start.as_deref() == Some("1") {
        let flow_id = uuid::Uuid::new_v4().to_string();
        let signed_state = sign_state(&flow_id, &return_to, q.invite.as_deref(), &state.state_signing_key);
        let nonce = uuid::Uuid::new_v4().to_string();
        let callback_url = format!("{}/callback", state.base_url);
        let auth_url = state.idp.authorization_url(&callback_url, &signed_state, &nonce);
        let mut resp = Redirect::to(&auth_url).into_response();
        no_cache_headers(&mut resp);
        return resp;
    }

    // Show login page (minimal HTML with auto-redirect)
    let flow_id = uuid::Uuid::new_v4().to_string();
    let signed_state = sign_state(&flow_id, &return_to, q.invite.as_deref(), &state.state_signing_key);
    let nonce = uuid::Uuid::new_v4().to_string();
    let callback_url = format!("{}/callback", state.base_url);
    let auth_url = state.idp.authorization_url(&callback_url, &signed_state, &nonce);

    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Login</title></head>
<body><p>Redirecting to login...</p>
<a href="{}">Click here if not redirected</a>
<script>window.location.href="{}";</script>
</body></html>"#,
        auth_url, auth_url
    );
    let mut resp = Html(html).into_response();
    no_cache_headers(&mut resp);
    resp
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

/// GET /callback — OIDC provider callback.
pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    // Check for IdP error
    if let Some(ref err) = q.error {
        return ApiError::bad_request("OIDC_FAILED", &format!("OIDC failed: {}", err)).into_response();
    }

    let code = match &q.code {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };
    let signed_state = match &q.state {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };

    // Verify state signature
    let (_flow_id, return_to, _invite) = match verify_state(&signed_state, &state.state_signing_key) {
        Some(v) => v,
        None => return ApiError::bad_request("INVALID_STATE", "Invalid or tampered state parameter").into_response(),
    };

    if is_json_accept(&headers) {
        // JSON mode — complete immediately
        match complete_oidc(&state, &code, &return_to).await {
            Ok((session_id, redirect_to)) => {
                let mut resp = Json(serde_json::json!({"redirect_to": redirect_to})).into_response();
                set_session_cookie(&mut resp, &session_id, &state);
                no_cache_headers(&mut resp);
                resp
            }
            Err(e) => e.into_response(),
        }
    } else {
        // HTML mode — return auto-submit form (Java compat)
        let html = format!(
            r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Completing login...</title></head>
<body><form id="f" method="POST" action="{}/auth/callback/complete">
<input type="hidden" name="code" value="{}">
<input type="hidden" name="state" value="{}">
</form><script>document.getElementById('f').submit();</script>
</body></html>"#,
            state.base_url, code, signed_state
        );
        let mut resp = Html(html).into_response();
        no_cache_headers(&mut resp);
        resp
    }
}

#[derive(Deserialize)]
pub struct CallbackCompleteBody {
    pub code: Option<String>,
    pub state: Option<String>,
}

/// POST /auth/callback/complete — complete OIDC flow from form submit.
pub async fn callback_complete(
    State(state): State<AppState>,
    body: axum::extract::Form<CallbackCompleteBody>,
) -> Response {
    let code = match &body.code {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };
    let signed_state = match &body.state {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };

    let (_flow_id, return_to, _invite) = match verify_state(&signed_state, &state.state_signing_key) {
        Some(v) => v,
        None => return ApiError::bad_request("INVALID_STATE", "Invalid or tampered state parameter").into_response(),
    };

    match complete_oidc(&state, &code, &return_to).await {
        Ok((session_id, redirect_to)) => {
            let mut resp = Redirect::to(&redirect_to).into_response();
            set_session_cookie(&mut resp, &session_id, &state);
            no_cache_headers(&mut resp);
            resp
        }
        Err(e) => e.into_response(),
    }
}

/// Shared OIDC completion logic.
async fn complete_oidc(
    state: &AppState,
    code: &str,
    return_to: &str,
) -> Result<(String, String), ApiError> {
    let callback_url = format!("{}/callback", state.base_url);

    let result = volta_auth_core::service::AuthService {
        idp: volta_auth_core::idp::IdpClient::new(
            volta_auth_core::idp::IdpConfig {
                provider: state.idp.provider().to_string(),
                client_id: String::new(), // filled by idp
                client_secret: String::new(),
                issuer_url: None,
                auth_url: None,
                token_url: None,
                userinfo_url: None,
                scopes: vec![],
            },
        ),
        user_store: std::sync::Arc::new(state.db.clone()),
        tenant_store: std::sync::Arc::new(state.db.clone()),
        membership_store: std::sync::Arc::new(state.db.clone()),
        invitation_store: std::sync::Arc::new(state.db.clone()),
        session_store: std::sync::Arc::new(state.db.clone()),
        jwt_issuer: state.jwt_issuer.clone(),
    };

    // Use IdpClient directly for the token exchange + userinfo
    let token_resp = state.idp.exchange_code(code, &callback_url).await
        .map_err(|e| ApiError::bad_request("OIDC_FAILED", &format!("Authentication failed: {}", e)))?;

    let userinfo = state.idp.userinfo(&token_resp.access_token).await
        .map_err(|e| ApiError::bad_request("OIDC_FAILED", &format!("Authentication failed: {}", e)))?;

    // #14: NFC-normalize + lowercase before store/compare to prevent homoglyph bypass.
    let email = userinfo.email.clone()
        .map(|e| crate::security::normalize_email(&e))
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ApiError::bad_request("OIDC_FAILED", "IdP did not return email"))?;

    // Upsert user
    let now = chrono::Utc::now();
    let user = UserStore::upsert(&state.db, volta_auth_core::record::UserRecord {
        id: uuid::Uuid::new_v4(),
        email: email.clone(),
        display_name: userinfo.name.clone(),
        google_sub: Some(userinfo.sub.clone()),
        created_at: now,
        is_active: true,
        locale: None,
        deleted_at: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    // Resolve tenant + roles
    let tenants = TenantStore::find_by_user(&state.db, user.id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let (tenant_id, tenant_slug, roles) = if let Some(t) = tenants.first() {
        let membership = MembershipStore::find(&state.db, user.id, t.id).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        let role = membership.map(|m| m.role).unwrap_or_else(|| "MEMBER".into());
        (t.id.to_string(), Some(t.slug.clone()), vec![role])
    } else {
        let slug = email.split('@').next().unwrap_or("user").to_string();
        let display = user.display_name.clone().unwrap_or_else(|| email.clone());
        let tenant = TenantStore::create_personal(&state.db, user.id, &display, &slug).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        (tenant.id.to_string(), Some(tenant.slug), vec!["OWNER".into()])
    };

    // Create session
    let session_id = uuid::Uuid::new_v4().to_string();
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    let tenant_id_for_event = tenant_id.clone();
    SessionStore::create(&state.db, volta_auth_core::record::SessionRecord {
        session_id: session_id.clone(),
        user_id: user.id.to_string(),
        tenant_id,
        return_to: Some(return_to.to_string()),
        created_at: now_epoch,
        last_active_at: now_epoch,
        expires_at: now_epoch + state.session_ttl_secs,
        invalidated_at: None,
        mfa_verified_at: None,
        ip_address: None,
        user_agent: None,
        csrf_token: None,
        email: Some(email),
        tenant_slug,
        roles,
        display_name: user.display_name,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    // P1.2: publish auth event for /viz/auth/stream subscribers.
    state.auth_events.publish(
        crate::auth_events::AuthEvent::now("LOGIN_SUCCESS")
            .with_user(user.id.to_string())
            .with_tenant(tenant_id_for_event)
            .with_session(session_id.clone()),
    );

    Ok((session_id, return_to.to_string()))
}
