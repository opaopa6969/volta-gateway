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
use crate::helpers::{is_json_accept, require_session, set_session_cookie};
use axum_extra::extract::CookieJar;
use crate::state::AppState;

use volta_auth_core::idp::PkcePair;
use volta_auth_core::record::OidcFlowRecord;
use volta_auth_core::store::{
    MembershipStore, OidcFlowStore, SessionStore, TenantStore, UserStore,
};

/// Flow TTL — long enough for the user to click through IdP consent, short
/// enough to keep leaked `?state=…` values useless.
const FLOW_TTL_SECS: i64 = 600;

/// HTML-escape for attribute/text contexts.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Produce a safe JS string *literal* (quotes included) for inline `<script>`.
fn js_literal(s: &str) -> String {
    serde_json::to_string(s)
        .unwrap_or_else(|_| "\"\"".into())
        .replace("</", "<\\/")
}

/// Shared WebAuthn base64url helpers injected into both pages.
const WEBAUTHN_JS: &str = r#"
function b64urlToBuf(s){s=s.replace(/-/g,'+').replace(/_/g,'/');const p=s.length%4;if(p)s+='='.repeat(4-p);const b=atob(s);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer;}
function bufToB64url(buf){const u=new Uint8Array(buf);let s='';for(let i=0;i<u.length;i++)s+=String.fromCharCode(u[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function assertionJSON(c){const r=c.response;return {id:c.id,rawId:bufToB64url(c.rawId),type:c.type,extensions:c.getClientExtensionResults?c.getClientExtensionResults():{},response:{authenticatorData:bufToB64url(r.authenticatorData),clientDataJSON:bufToB64url(r.clientDataJSON),signature:bufToB64url(r.signature),userHandle:r.userHandle?bufToB64url(r.userHandle):null}};}
function attestationJSON(c){const r=c.response;return {id:c.id,rawId:bufToB64url(c.rawId),type:c.type,extensions:c.getClientExtensionResults?c.getClientExtensionResults():{},response:{attestationObject:bufToB64url(r.attestationObject),clientDataJSON:bufToB64url(r.clientDataJSON)}};}
"#;

const PAGE_STYLE: &str = r#"<style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem;text-align:center}h1{font-size:1.3rem}.btn{display:block;width:100%;padding:.8rem;margin:.6rem 0;border:1px solid #ccc;border-radius:8px;background:#fff;font-size:1rem;cursor:pointer;text-decoration:none;color:#222;box-sizing:border-box}.btn.g{background:#4285f4;color:#fff;border-color:#4285f4}#status{margin-top:1rem;min-height:1.2em;font-size:.9rem}</style>"#;

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

    // Choice page (parity with Java /login): Google OR discoverable passkey.
    let template = r#"<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ログイン</title>__STYLE__</head><body>
<h1>Volta にログイン</h1>
<a class="btn g" href="__AUTH_URL__">Google でログイン</a>
<button class="btn" onclick="passkeyLogin()">パスキーでログイン</button>
<div id="status"></div>
<script>
const RETURN_TO = __RETURN_TO__;
__WEBAUTHN_JS__
async function passkeyLogin(){const st=document.getElementById('status');st.style.color='#b00';st.textContent='';try{const r=await fetch('/auth/passkey/discover/start',{method:'POST',headers:{'Accept':'application/json'}});if(!r.ok)throw new Error('開始に失敗('+r.status+')');const d=await r.json();const pk=d.options.publicKey;pk.challenge=b64urlToBuf(pk.challenge);(pk.allowCredentials||[]).forEach(c=>c.id=b64urlToBuf(c.id));const cred=await navigator.credentials.get({publicKey:pk});const fr=await fetch('/auth/passkey/discover/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({challenge_id:d.challenge_id,credential:assertionJSON(cred)})});if(!fr.ok){const e=await fr.json().catch(()=>({}));throw new Error((e.error&&e.error.message)||('finish '+fr.status));}window.location.href=RETURN_TO;}catch(err){st.textContent='パスキーログイン失敗: '+err.message;}}
</script></body></html>"#;
    let html = template
        .replace("__STYLE__", PAGE_STYLE)
        .replace("__AUTH_URL__", &html_escape(&auth_url))
        .replace("__RETURN_TO__", &js_literal(&return_to))
        .replace("__WEBAUTHN_JS__", WEBAUTHN_JS);
    let mut resp = Html(html).into_response();
    no_cache_headers(&mut resp);
    resp
}

/// GET / — landing page. Session-aware so we never bounce an already
/// authenticated user back into the OIDC redirect (which would loop:
/// `/` → `/login` → IdP → `/callback` → return_to `/` → …). Authenticated →
/// minimal "signed in" page; otherwise → `/login`.
pub async fn root(State(state): State<AppState>, jar: CookieJar) -> Response {
    match require_session(&state, &jar).await {
        Ok(session) => {
            let email = session.email.unwrap_or_default();
            let template = r#"<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Volta Auth</title>__STYLE__</head><body>
<h1>サインイン済み</h1><p>__EMAIL__</p>
<button class="btn" onclick="registerPasskey()">このデバイスにパスキーを登録</button>
<a class="btn" href="/auth/logout">サインアウト</a>
<div id="status"></div>
<script>
const USER_ID = "__USER_ID__";
__WEBAUTHN_JS__
async function registerPasskey(){const st=document.getElementById('status');st.style.color='#b00';st.textContent='';try{const r=await fetch('/api/v1/users/'+USER_ID+'/passkeys/register/start',{method:'POST',headers:{'Accept':'application/json','content-type':'application/json'},body:'{}'});if(!r.ok)throw new Error('開始に失敗('+r.status+')');const d=await r.json();const pk=d.options.publicKey;pk.challenge=b64urlToBuf(pk.challenge);pk.user.id=b64urlToBuf(pk.user.id);(pk.excludeCredentials||[]).forEach(c=>c.id=b64urlToBuf(c.id));const cred=await navigator.credentials.create({publicKey:pk});const fr=await fetch('/api/v1/users/'+USER_ID+'/passkeys/register/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({challenge_id:d.challenge_id,name:'My Passkey',credential:attestationJSON(cred)})});if(!fr.ok){const e=await fr.json().catch(()=>({}));throw new Error((e.error&&e.error.message)||('finish '+fr.status));}st.style.color='#070';st.textContent='パスキー登録完了！サインアウトして「パスキーでログイン」を試せます。';}catch(err){st.textContent='登録失敗: '+err.message;}}
</script></body></html>"#;
            let html = template
                .replace("__STYLE__", PAGE_STYLE)
                .replace("__EMAIL__", &html_escape(&email))
                .replace("__USER_ID__", &html_escape(&session.user_id))
                .replace("__WEBAUTHN_JS__", WEBAUTHN_JS);
            let mut resp = Html(html).into_response();
            no_cache_headers(&mut resp);
            resp
        }
        Err(_) => Redirect::to("/login").into_response(),
    }
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

    // Backlog P1 #4: verify id_token when the IdP config declares an issuer.
    // Providers without `issuer_url` (plain OAuth2 like GitHub) keep the old
    // `userinfo`-only path.
    let id_token_sub: Option<String> = if let (Some(ref id_token), Some(ref issuer)) =
        (token_resp.id_token.as_ref(), state.idp.config().issuer_url.as_ref())
    {
        let verifier = volta_auth_core::oidc::IdTokenVerifier::from_issuer(
            issuer.trim_end_matches('/'),
            &state.idp.config().client_id,
        );
        match verifier
            .verify(id_token, &flow.nonce, &token_resp.access_token)
            .await
        {
            Ok(claims) => Some(claims.sub),
            Err(e) => {
                return Err(ApiError::unauthorized(
                    "OIDC_ID_TOKEN_INVALID",
                    &format!("id_token verification failed: {}", e),
                ));
            }
        }
    } else {
        None
    };

    let userinfo = state.idp.userinfo(&token_resp.access_token).await
        .map_err(|e| ApiError::bad_request("OIDC_FAILED", &format!("Authentication failed: {}", e)))?;

    // #14: NFC-normalize + lowercase before store/compare.
    let email = userinfo.email.clone()
        .map(|e| crate::security::normalize_email(&e))
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ApiError::bad_request("OIDC_FAILED", "IdP did not return email"))?;

    let now = chrono::Utc::now();
    // Prefer id_token's sub when we verified it (spec §3.1.3.7); otherwise
    // fall back to userinfo.sub as before.
    let sub = id_token_sub.unwrap_or_else(|| userinfo.sub.clone());
    let user = UserStore::upsert(&state.db, volta_auth_core::record::UserRecord {
        id: uuid::Uuid::new_v4(),
        email: email.clone(),
        display_name: userinfo.name.clone(),
        google_sub: Some(sub),
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

    state.auth_events.publish_and_audit(
        crate::auth_events::AuthEvent::now("LOGIN_SUCCESS")
            .with_user(user.id.to_string())
            .with_tenant(tenant_id_for_event)
            .with_session(session_id.clone()),
        &state.db,
        None,                               // actor_ip: OIDC completion has no direct request headers here
        Some("SESSION".into()),
        Some(session_id.clone()),
        None,
    ).await;

    Ok((session_id, return_to))
}
