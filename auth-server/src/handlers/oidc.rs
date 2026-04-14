//! OIDC login + callback handlers.
//!
//! Backlog P0 #1: flows now persist in `oidc_flows` with PKCE
//! `code_verifier` stored encrypted. The previous HMAC-signed stateless
//! `state` parameter is gone — Java's `OidcFlowRouter` / `OidcStateCodec`
//! uses the same DB-backed single-use model and Rust now matches.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{is_json_accept, set_session_cookie};
use crate::state::AppState;

use volta_auth_core::idp::PkcePair;
use volta_auth_core::record::OidcFlowRecord;
use volta_auth_core::store::{
    MembershipStore, OidcFlowStore, SessionStore, TenantStore, UserStore,
};

/// Flow TTL — long enough for the user to click through IdP consent, short
/// enough to keep leaked `?state=…` values useless.
const FLOW_TTL_SECS: i64 = 600;

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
    let callback_url = format!("{}/callback", state.base_url);

    // Build the flow + redirect for both eager (`?start=1`) and lazy (plain
    // /login) paths. The lazy path just wraps the same URL in a minimal HTML.
    let auth_url = match begin_oidc_flow(&state, &return_to, q.invite.as_deref(), &callback_url).await {
        Ok(url) => url,
        Err(e) => return e.into_response(),
    };

    if q.start.as_deref() == Some("1") {
        let mut resp = Redirect::to(&auth_url).into_response();
        no_cache_headers(&mut resp);
        return resp;
    }

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

/// Create a fresh `oidc_flows` row and return the IdP authorization URL.
async fn begin_oidc_flow(
    state: &AppState,
    return_to: &str,
    invite: Option<&str>,
    callback_url: &str,
) -> Result<String, ApiError> {
    let flow_id = uuid::Uuid::new_v4();
    let opaque_state = random_state();
    let nonce = random_state();
    let pkce = PkcePair::generate();

    let encrypted = state.key_cipher.encrypt(pkce.verifier.as_bytes());

    let expires = chrono::Utc::now() + chrono::Duration::seconds(FLOW_TTL_SECS);
    OidcFlowStore::save(
        &state.db,
        OidcFlowRecord {
            id: flow_id,
            state: opaque_state.clone(),
            nonce: nonce.clone(),
            code_verifier_encrypted: encrypted,
            return_to: Some(return_to.to_string()),
            invite_code: invite.map(String::from),
            tenant_id: None,
            created_at: chrono::Utc::now(),
            expires_at: expires,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(state
        .idp
        .authorization_url_pkce(callback_url, &opaque_state, &nonce, Some(&pkce.challenge)))
}

/// 32 random bytes → URL-safe-base64 with no padding. Opaque to the IdP and
/// indistinguishable from prior HMAC-format states from an external observer.
fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
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
    if let Some(ref err) = q.error {
        return ApiError::bad_request("OIDC_FAILED", &format!("OIDC failed: {}", err)).into_response();
    }

    let code = match &q.code {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };
    let opaque_state = match &q.state {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };

    // Single-use consume — the second callback with the same state fails.
    let flow = match OidcFlowStore::consume(&state.db, &opaque_state).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return ApiError::bad_request(
                "INVALID_STATE",
                "Invalid or expired state parameter",
            )
            .into_response();
        }
        Err(e) => return ApiError::internal(&e.to_string()).into_response(),
    };

    if is_json_accept(&headers) {
        match complete_oidc(&state, &code, &flow).await {
            Ok((session_id, redirect_to)) => {
                let mut resp = Json(serde_json::json!({"redirect_to": redirect_to})).into_response();
                set_session_cookie(&mut resp, &session_id, &state);
                no_cache_headers(&mut resp);
                resp
            }
            Err(e) => e.into_response(),
        }
    } else {
        // HTML mode — Java compat: re-POST the code to /auth/callback/complete
        // so that the browser discards the fragment/URL parameters and lands
        // on a clean page. We include the *opaque* state here so the POST
        // handler can look up the flow — but the flow was already consumed
        // above, so instead we re-encrypt a one-shot marker. Simpler: just
        // complete here (same as JSON path). The auto-POST form is kept for
        // browsers that want to hide the code from history.
        match complete_oidc(&state, &code, &flow).await {
            Ok((session_id, redirect_to)) => {
                let mut resp = Redirect::to(&redirect_to).into_response();
                set_session_cookie(&mut resp, &session_id, &state);
                no_cache_headers(&mut resp);
                resp
            }
            Err(e) => e.into_response(),
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackCompleteBody {
    pub code: Option<String>,
    pub state: Option<String>,
}

/// POST /auth/callback/complete — complete OIDC flow from form submit.
///
/// Retained for Java-compat; the GET callback path above now completes inline,
/// so this endpoint is called only by callers that intentionally defer
/// completion (e.g., JS flows that want to POST from the front-end).
pub async fn callback_complete(
    State(state): State<AppState>,
    body: axum::extract::Form<CallbackCompleteBody>,
) -> Response {
    let code = match &body.code {
        Some(c) if !c.is_empty() => c.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };
    let opaque_state = match &body.state {
        Some(s) if !s.is_empty() => s.clone(),
        _ => return ApiError::bad_request("BAD_REQUEST", "code/state is required").into_response(),
    };

    let flow = match OidcFlowStore::consume(&state.db, &opaque_state).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return ApiError::bad_request("INVALID_STATE", "Invalid or expired state parameter")
                .into_response();
        }
        Err(e) => return ApiError::internal(&e.to_string()).into_response(),
    };

    match complete_oidc(&state, &code, &flow).await {
        Ok((session_id, redirect_to)) => {
            let mut resp = Redirect::to(&redirect_to).into_response();
            set_session_cookie(&mut resp, &session_id, &state);
            no_cache_headers(&mut resp);
            resp
        }
        Err(e) => e.into_response(),
    }
}

/// Shared OIDC completion logic — runs once the `oidc_flows` row has been
/// consumed atomically above.
async fn complete_oidc(
    state: &AppState,
    code: &str,
    flow: &OidcFlowRecord,
) -> Result<(String, String), ApiError> {
    let callback_url = format!("{}/callback", state.base_url);

    let verifier = state
        .key_cipher
        .decrypt(&flow.code_verifier_encrypted)
        .map_err(|e| {
            ApiError::internal(&format!("PKCE verifier decryption failed: {}", e))
        })?;
    let verifier_str = std::str::from_utf8(&verifier)
        .map_err(|_| ApiError::internal("PKCE verifier is not valid UTF-8"))?;

    let token_resp = state
        .idp
        .exchange_code_pkce(code, &callback_url, Some(verifier_str))
        .await
        .map_err(|e| ApiError::bad_request("OIDC_FAILED", &format!("Authentication failed: {}", e)))?;

    let userinfo = state.idp.userinfo(&token_resp.access_token).await
        .map_err(|e| ApiError::bad_request("OIDC_FAILED", &format!("Authentication failed: {}", e)))?;

    // #14: NFC-normalize + lowercase before store/compare.
    let email = userinfo.email.clone()
        .map(|e| crate::security::normalize_email(&e))
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ApiError::bad_request("OIDC_FAILED", "IdP did not return email"))?;

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

    let session_id = uuid::Uuid::new_v4().to_string();
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    let return_to = flow.return_to.clone().unwrap_or_else(|| format!("{}/", state.base_url));
    let tenant_id_for_event = tenant_id.clone();
    SessionStore::create(&state.db, volta_auth_core::record::SessionRecord {
        session_id: session_id.clone(),
        user_id: user.id.to_string(),
        tenant_id,
        return_to: Some(return_to.clone()),
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

    state.auth_events.publish(
        crate::auth_events::AuthEvent::now("LOGIN_SUCCESS")
            .with_user(user.id.to_string())
            .with_tenant(tenant_id_for_event)
            .with_session(session_id.clone()),
    );

    Ok((session_id, return_to))
}
