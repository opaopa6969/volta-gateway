//! OAuth 2.0 Device Authorization Grant (RFC 8628).
//!
//! Input-constrained / native clients (CLI, TV, desktop app) obtain a
//! `device_code` (polled) plus a short human `user_code`. The user approves on a
//! second device by visiting `verification_uri` and entering the code — or by
//! scanning a QR that encodes `verification_uri_complete`. Approval is gated by
//! an authenticated session, so the issued token represents that user.
//!
//! Endpoints:
//!   POST /oauth/device_authorization   → issue device_code + user_code
//!   GET  /device[?user_code=…]         → approval page (requires login)
//!   POST /device/approve               → record approval
//!   POST /device/deny                  → record denial
//!   POST /oauth/token (device_code)    → poll for the token (see manage::oauth_token)

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::require_session;
use crate::state::AppState;
use volta_auth_core::crypto::{random_token_hex, random_user_code, sha256_hex};
use volta_auth_core::record::DeviceGrantRecord;
use volta_auth_core::store::*;

pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn device_ttl_secs(state: &AppState) -> i64 {
    std::env::var("DEVICE_CODE_TTL_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600)
        .max(60)
        .min(state.session_ttl_secs as i64)
}

/// RFC 8628 §3.5 error responses are `application/json` with HTTP 400 and an
/// `error` field. `authorization_pending` / `slow_down` are the polling states.
fn oauth_error(error: &str) -> Response {
    let mut resp = (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": error })),
    )
        .into_response();
    no_cache_headers(&mut resp);
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

// ─── POST /oauth/device_authorization ──────────────────────

#[derive(Deserialize)]
pub struct DeviceAuthReq {
    /// Public/native client identifier. Required (RFC 8628 §3.1).
    pub client_id: String,
    pub scope: Option<String>,
}

pub async fn device_authorization(
    State(s): State<AppState>,
    Form(b): Form<DeviceAuthReq>,
) -> Result<Response, ApiError> {
    if b.client_id.trim().is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "client_id is required",
        ));
    }
    let device_code = random_token_hex(32);
    let user_code = random_user_code();
    let interval: i32 = 5;
    let ttl = device_ttl_secs(&s);
    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl);

    DeviceGrantStore::create(
        &s.db,
        DeviceGrantRecord {
            id: Uuid::new_v4(),
            device_code_hash: sha256_hex(&device_code),
            user_code: user_code.clone(),
            client_id: b.client_id,
            scope: b.scope.filter(|s| !s.is_empty()),
            status: "pending".into(),
            user_id: None,
            tenant_id: None,
            interval_secs: interval,
            last_polled_at: None,
            created_at: chrono::Utc::now(),
            expires_at,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    let verification_uri = format!("{}/device", s.base_url);
    let verification_uri_complete = format!("{}/device?user_code={}", s.base_url, user_code);

    let mut resp = Json(serde_json::json!({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": verification_uri,
        "verification_uri_complete": verification_uri_complete,
        "expires_in": ttl,
        "interval": interval,
    }))
    .into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ─── GET /device[?user_code=…] — approval page ─────────────

#[derive(Deserialize)]
pub struct DevicePageQuery {
    pub user_code: Option<String>,
}

pub async fn device_verification_page(
    State(s): State<AppState>,
    jar: CookieJar,
    Query(q): Query<DevicePageQuery>,
) -> Response {
    // Approval must be tied to a real identity → require login, bouncing back
    // here (with the code preserved) after sign-in.
    if require_session(&s, &jar).await.is_err() {
        let raw = match &q.user_code {
            Some(c) => format!("/device?user_code={}", c),
            None => "/device".to_string(),
        };
        let return_to = urlencode(&raw);
        let mut resp =
            Redirect::to(&format!("{}/login?return_to={}", s.base_url, return_to)).into_response();
        no_cache_headers(&mut resp);
        return resp;
    }

    // If a code was supplied, look it up to show the requesting client + scope.
    let (prefill, client_line) = match &q.user_code {
        Some(code) => {
            match DeviceGrantStore::find_pending_by_user_code(&s.db, &code.to_uppercase()).await {
                Ok(Some(g)) => {
                    let scope = g
                        .scope
                        .as_deref()
                        .map(|s| format!(" — 権限: {}", html_escape(s)))
                        .unwrap_or_default();
                    (html_escape(code), format!("<p class=\"client\">アプリ <b>{}</b>{} がサインインを求めています。</p>", html_escape(&g.client_id), scope))
                }
                _ => (
                    html_escape(code),
                    "<p class=\"client warn\">このコードは無効か、期限切れです。</p>".to_string(),
                ),
            }
        }
        None => (String::new(), String::new()),
    };

    let html = DEVICE_PAGE_HTML
        .replace("__PREFILL__", &prefill)
        .replace("__CLIENT__", &client_line);
    let mut resp = Html(html).into_response();
    no_cache_headers(&mut resp);
    resp
}

// ─── POST /device/approve · /device/deny ───────────────────

#[derive(Deserialize)]
pub struct DeviceDecisionReq {
    pub user_code: String,
}

async fn decide(
    s: &AppState,
    jar: &CookieJar,
    user_code: &str,
    approve: bool,
) -> Result<Response, ApiError> {
    let session = require_session(s, jar).await?;
    let user_id: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    let tenant_id: Uuid = session
        .tenant_id
        .parse()
        .map_err(|_| ApiError::internal("bad tenant id"))?;
    let code = user_code.trim().to_uppercase();

    let outcome = DeviceGrantStore::decide(&s.db, &code, approve, user_id, tenant_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    match outcome {
        DeviceDecisionOutcome::Ok { .. } => {
            Ok(Json(serde_json::json!({ "ok": true, "approved": approve })).into_response())
        }
        DeviceDecisionOutcome::NotFound => Err(ApiError::bad_request(
            "invalid_user_code",
            "コードが見つかりません",
        )),
        DeviceDecisionOutcome::Expired => Err(ApiError::bad_request(
            "expired_user_code",
            "コードの期限が切れています",
        )),
        DeviceDecisionOutcome::AlreadyResolved => Err(ApiError::bad_request(
            "already_resolved",
            "このコードは既に処理済みです",
        )),
    }
}

pub async fn device_approve(
    State(s): State<AppState>,
    jar: CookieJar,
    Form(b): Form<DeviceDecisionReq>,
) -> Result<Response, ApiError> {
    decide(&s, &jar, &b.user_code, true).await
}

pub async fn device_deny(
    State(s): State<AppState>,
    jar: CookieJar,
    Form(b): Form<DeviceDecisionReq>,
) -> Result<Response, ApiError> {
    decide(&s, &jar, &b.user_code, false).await
}

// ─── device_code token grant (called from manage::oauth_token) ─────

/// Handle `grant_type=urn:ietf:params:oauth:grant-type:device_code` on the token
/// endpoint. Returns the RFC 8628 polling responses until the user approves.
pub async fn device_token_grant(s: &AppState, device_code: &str) -> Response {
    let hash = sha256_hex(device_code);
    let outcome = match DeviceGrantStore::poll(&s.db, &hash).await {
        Ok(o) => o,
        Err(e) => {
            let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "server_error", "error_description": e.to_string() }))).into_response();
            no_cache_headers(&mut resp);
            return resp;
        }
    };

    let (user_id, tenant_id, scope) = match outcome {
        DevicePollOutcome::Approved {
            user_id,
            tenant_id,
            scope,
        } => (user_id, tenant_id, scope),
        DevicePollOutcome::Pending => return oauth_error("authorization_pending"),
        DevicePollOutcome::SlowDown => return oauth_error("slow_down"),
        DevicePollOutcome::Denied => return oauth_error("access_denied"),
        DevicePollOutcome::Expired => return oauth_error("expired_token"),
        DevicePollOutcome::NotFound => return oauth_error("invalid_grant"),
    };

    // Resolve claims for the approving identity (email + tenant role).
    let user = UserStore::find_by_id(&s.db, user_id).await.ok().flatten();
    let role = MembershipStore::find(&s.db, user_id, tenant_id)
        .await
        .ok()
        .flatten()
        .map(|m| m.role);

    let jwt = match s.jwt_issuer.issue(&volta_auth_core::jwt::VoltaClaims {
        sub: user_id.to_string(),
        email: user.as_ref().map(|u| u.email.clone()),
        tenant_id: Some(tenant_id.to_string()),
        tenant_slug: None,
        roles: role,
        name: user.as_ref().and_then(|u| u.display_name.clone()),
        app_id: None,
        iat: None,
        exp: None,
    }) {
        Ok(j) => j,
        Err(e) => {
            let mut resp = (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "server_error", "error_description": e.to_string() }))).into_response();
            no_cache_headers(&mut resp);
            return resp;
        }
    };

    // Single-use: invalidate the grant now that a token was issued.
    let _ = DeviceGrantStore::consume(&s.db, &hash).await;

    let mut resp = Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": s.session_ttl_secs,
        "scope": scope,
    }))
    .into_response();
    no_cache_headers(&mut resp);
    resp
}

fn urlencode(s: &str) -> String {
    // Minimal percent-encoding for a path we control (encode the chars that
    // matter inside a query value: space, ?, &, #, =, +).
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

const DEVICE_PAGE_HTML: &str = r##"<!DOCTYPE html><html lang="ja"><head>
<meta charset="utf-8"><title>デバイス認可 — volta</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:380px;width:100%}
h1{margin:0 0 8px;font-size:20px}
p{color:#666;margin:0 0 16px;font-size:14px}
.client{background:#f0f4ff;border:1px solid #d5e0ff;border-radius:6px;padding:12px}
.client.warn{background:#fff4f4;border-color:#ffd5d5;color:#c62828}
input{width:100%;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:18px;box-sizing:border-box;margin-bottom:12px;letter-spacing:3px;text-align:center;text-transform:uppercase}
.row{display:flex;gap:8px}
button{flex:1;padding:12px;border:0;border-radius:6px;font-size:16px;cursor:pointer}
.approve{background:#0f3460;color:#fff}.approve:hover{background:#16213e}
.deny{background:#eee;color:#333}.deny:hover{background:#ddd}
.msg{font-size:14px;min-height:20px;margin-top:12px}
.ok{color:#2e7d32}.err{color:#c62828}
</style></head><body>
<form class="card" id="f">
  <h1>デバイスの認可</h1>
  __CLIENT__
  <p>デバイスに表示されたコードを確認し、承認してください。</p>
  <input name="user_code" id="code" value="__PREFILL__" autocomplete="off" autocapitalize="characters" placeholder="XXXX-XXXX" required>
  <div class="row">
    <button type="submit" class="approve">承認する</button>
    <button type="button" class="deny" id="denyBtn">拒否</button>
  </div>
  <div class="msg" id="m"></div>
</form>
<script>
const f=document.getElementById('f'),m=document.getElementById('m'),code=document.getElementById('code');
async function send(url){
  m.textContent='';m.className='msg';
  const body=new URLSearchParams({user_code:code.value.trim()});
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Accept':'application/json'},credentials:'include',body});
  if(r.ok){const j=await r.json();m.className='msg ok';m.textContent=j.approved?'✅ 承認しました。デバイスに戻ってください。':'拒否しました。';}
  else{try{const j=await r.json();m.className='msg err';m.textContent=j.message||'エラーが発生しました';}catch{m.className='msg err';m.textContent='エラーが発生しました';}}
}
f.addEventListener('submit',e=>{e.preventDefault();send('/device/approve');});
document.getElementById('denyBtn').addEventListener('click',()=>send('/device/deny'));
</script></body></html>"##;
