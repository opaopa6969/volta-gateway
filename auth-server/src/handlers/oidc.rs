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
use crate::helpers::{is_json_accept, read_device_marker, require_session, set_device_cookie, set_session_cookie};
use axum_extra::extract::CookieJar;
use crate::state::AppState;

use volta_auth_core::crypto::{random_token_hex, sha256_hex};
use volta_auth_core::idp::PkcePair;
use volta_auth_core::record::OidcFlowRecord;
use volta_auth_core::risk::{self, RiskDecision, RiskSignals, RiskThresholds};
use volta_auth_core::store::{
    MembershipStore, OidcFlowStore, RiskDeviceStore, SessionStepUpStore, SessionStore, TenantStore, UserIdentityStore, UserStore,
};

/// Per-request context feeding risk-based adaptive auth (Phase 4c).
pub struct RiskContext {
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    /// SHA-256 of the `__volta_kd` device marker (raw value never stored).
    pub device_hash: String,
}

/// First hop of `X-Forwarded-For` (set by the gateway), else `X-Real-IP`.
fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()).map(|s| s.to_string()))
}
fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

/// Resolve (or mint) the device id from the request, returning
/// `(device_id_to_set_as_cookie, RiskContext)`.
fn build_risk_context(headers: &HeaderMap, jar: &CookieJar) -> (String, RiskContext) {
    let device_id = read_device_marker(jar).unwrap_or_else(|| random_token_hex(16));
    let ctx = RiskContext {
        client_ip: client_ip(headers),
        user_agent: user_agent(headers),
        device_hash: sha256_hex(&device_id),
    };
    (device_id, ctx)
}

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
// Phase 3: translate opaque WebAuthn / server errors into next-action guidance.
function passkeyErr(err){const n=err&&err.name;if(n==='NotAllowedError')return '中断またはタイムアウトしました。もう一度お試しください。';if(n==='InvalidStateError')return 'このデバイスには既にパスキーが登録されています。';if(n==='AbortError')return '操作がキャンセルされました。';if(n==='SecurityError')return 'セキュリティエラー（ドメイン設定をご確認ください）。';if(n==='NotSupportedError')return 'このブラウザ/端末はパスキーに対応していません。';return (err&&err.message)||'エラーが発生しました。';}
async function serverErrText(resp,fallback){try{const e=await resp.json();if(e&&e.error&&e.error.message){const m=e.error.message;if(/no matching credential/i.test(m))return 'このアカウントのパスキーが見つかりません。先に登録してください。';if(/verification failed/i.test(m))return 'パスキーの検証に失敗しました。';return m;}}catch(_){}return fallback+' ('+resp.status+')';}
"#;

const PAGE_STYLE: &str = r#"<style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem;text-align:center}h1{font-size:1.3rem}.btn{display:block;width:100%;padding:.8rem;margin:.6rem 0;border:1px solid #ccc;border-radius:8px;background:#fff;font-size:1rem;cursor:pointer;text-decoration:none;color:#222;box-sizing:border-box}.btn.g{background:#4285f4;color:#fff;border-color:#4285f4}#status{margin-top:1rem;min-height:1.2em;font-size:.9rem}</style>"#;

#[derive(Deserialize)]
pub struct LoginQuery {
    pub start: Option<String>,
    pub return_to: Option<String>,
    pub invite: Option<String>,
    /// `add=1` → "add another account" (multi-account). Remembers the current
    /// active session and forces the upstream IdP's account chooser
    /// (`prompt=select_account`) so the user can pick a *different* account.
    pub add: Option<String>,
}

/// GET /login — show login page or start OIDC redirect.
pub async fn login(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    let return_to = q.return_to.unwrap_or_else(|| format!("{}/", state.base_url));
    let callback_url = format!("{}/callback", state.base_url);
    let adding = q.add.as_deref() == Some("1");
    // Multi-account: force the IdP chooser so "add account" doesn't silently
    // re-select the same upstream identity.
    let prompt = if adding { Some("select_account") } else { None };

    // Build the flow + redirect for both eager (`?start=1`) and lazy (plain
    // /login) paths. The lazy path just wraps the same URL in a minimal HTML.
    let auth_url = match begin_oidc_flow(&state, &return_to, q.invite.as_deref(), &callback_url, prompt).await {
        Ok(url) => url,
        Err(e) => return e.into_response(),
    };

    // "Add account": before the login overwrites `__volta_session` with the new
    // identity, remember the current active session in the accounts list so both
    // survive. (Reconciliation of the *new* session happens on /accounts.)
    if adding {
        let mut accounts = crate::helpers::read_accounts(&jar);
        if let Some(active) = crate::helpers::extract_session_id(&jar) {
            if !accounts.contains(&active) { accounts.insert(0, active); }
        }
        let mut resp = Redirect::to(&auth_url).into_response();
        crate::helpers::set_accounts_cookie(&mut resp, &accounts, &state);
        no_cache_headers(&mut resp);
        return resp;
    }

    if q.start.as_deref() == Some("1") {
        let mut resp = Redirect::to(&auth_url).into_response();
        no_cache_headers(&mut resp);
        return resp;
    }

    // Google-style login (passkey-ux-design.md):
    //  - Phase 1: conditional UI — passkeys surface in the input's autofill on
    //    load (mediation:'conditional'); no button hunt. Explicit button stays
    //    as a modal fallback. One conditional get() is aborted before a modal
    //    get() to avoid the "request already pending" conflict.
    //  - Phase 3: WebAuthn/server errors translated to next-action guidance.
    let template = r#"<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ログイン</title>__STYLE__</head><body>
<h1>Volta にログイン</h1>
<input id="uname" name="username" autocomplete="username webauthn" placeholder="メールアドレス（パスキー候補が表示されます）" style="width:100%;padding:.7rem;margin:.4rem 0;border:1px solid #ccc;border-radius:8px;box-sizing:border-box;font-size:.95rem">
<a class="btn g" href="__AUTH_URL__">Google でログイン</a>
<button class="btn" id="pk-btn" onclick="passkeyLogin()">パスキーでログイン</button>
<div id="status"></div>
<script>
const RETURN_TO = __RETURN_TO__;
__WEBAUTHN_JS__
let condAC = null;
async function discoverAndFinish(pk, challenge_id, mediation, signal){
  pk.challenge=b64urlToBuf(pk.challenge);
  (pk.allowCredentials||[]).forEach(c=>c.id=b64urlToBuf(c.id));
  const opts={publicKey:pk};
  if(mediation) opts.mediation=mediation;
  if(signal) opts.signal=signal;
  const cred=await navigator.credentials.get(opts);
  const fr=await fetch('/auth/passkey/discover/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({challenge_id,credential:assertionJSON(cred)})});
  if(!fr.ok) throw new Error(await serverErrText(fr,'ログインに失敗'));
  window.location.href=RETURN_TO;
}
// Phase 1: conditional UI (autofill). Silent — never shows errors.
async function startConditional(){
  try{
    if(!window.PublicKeyCredential||!PublicKeyCredential.isConditionalMediationAvailable)return;
    if(!(await PublicKeyCredential.isConditionalMediationAvailable()))return;
    const r=await fetch('/auth/passkey/discover/start',{method:'POST',headers:{'Accept':'application/json'}});
    if(!r.ok)return;
    const d=await r.json();
    condAC=new AbortController();
    await discoverAndFinish(d.options.publicKey,d.challenge_id,'conditional',condAC.signal);
  }catch(_){/* autofill aborted / no selection — stay on page silently */}
}
// Explicit modal fallback (button).
async function passkeyLogin(){const st=document.getElementById('status');st.style.color='#b00';st.textContent='';try{if(condAC){condAC.abort();condAC=null;}const r=await fetch('/auth/passkey/discover/start',{method:'POST',headers:{'Accept':'application/json'}});if(!r.ok)throw new Error('開始に失敗('+r.status+')');const d=await r.json();await discoverAndFinish(d.options.publicKey,d.challenge_id,null,null);}catch(err){st.textContent='パスキーログイン失敗: '+passkeyErr(err);}}
startConditional();
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
            // Account page: signed-in identity + passkey management (list /
            // add / delete) + sign out. This is the fallback landing for a
            // direct visit to the auth host (normal flows redirect to return_to).
            let template = r#"<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>アカウント — Volta Auth</title>__STYLE__</head><body>
<h1>アカウント</h1>
<p style="color:#555">サインイン中: <strong>__EMAIL__</strong></p>
<div id="enroll" style="display:none;border:1px solid #4285f4;border-radius:8px;padding:1rem;margin:.6rem 0;background:#f5f9ff">
<p style="margin:.2rem 0">次回からパスワード無しでログインできます。</p>
<button class="btn g" onclick="registerPasskey()">このデバイスにパスキーを登録</button>
</div>
<h2 style="font-size:1rem;margin:1.4rem 0 .4rem;text-align:left">登録済みパスキー</h2>
<div id="pk-list" style="font-size:.9rem">読み込み中...</div>
<button class="btn" id="add-btn" onclick="registerPasskey()" style="display:none">別のパスキーを追加</button>
<a class="btn" href="/accounts">アカウントを切り替え / 追加</a>
<a class="btn" href="/auth/logout">サインアウト</a>
<div id="status"></div>
<script>
const USER_ID = "__USER_ID__";
__WEBAUTHN_JS__
function fmtDate(s){if(!s)return '—';try{return new Date(s).toLocaleString('ja-JP');}catch(_){return s;}}
async function loadPasskeys(){
  const box=document.getElementById('pk-list');box.textContent='読み込み中...';
  let list=[];
  try{const r=await fetch('/api/v1/users/'+USER_ID+'/passkeys',{headers:{'Accept':'application/json'}});list=r.ok?await r.json():[];}catch(_){box.textContent='一覧の取得に失敗しました。';document.getElementById('add-btn').style.display='block';return;}
  box.textContent='';
  if(!Array.isArray(list)||list.length===0){box.textContent='まだ登録されていません。';}
  else{list.forEach(p=>{
    const row=document.createElement('div');row.style.cssText='display:flex;justify-content:space-between;align-items:center;border:1px solid #eee;border-radius:8px;padding:.5rem .7rem;margin:.3rem 0';
    const info=document.createElement('div');info.style.cssText='text-align:left';
    const nm=document.createElement('div');nm.textContent=p.name||'パスキー';nm.style.fontWeight='600';
    const meta=document.createElement('div');meta.style.cssText='color:#999;font-size:.78rem';meta.textContent='作成 '+fmtDate(p.created_at)+' / 最終 '+fmtDate(p.last_used_at);
    info.appendChild(nm);info.appendChild(meta);
    const del=document.createElement('button');del.textContent='削除';del.style.cssText='border:1px solid #d33;color:#d33;background:#fff;border-radius:6px;padding:.3rem .6rem;cursor:pointer';
    del.onclick=()=>deletePasskey(p.id);
    row.appendChild(info);row.appendChild(del);box.appendChild(row);
  });}
  let uvpaa=false;try{uvpaa=window.PublicKeyCredential?await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable():false;}catch(_){}
  const empty=!Array.isArray(list)||list.length===0;
  document.getElementById('enroll').style.display=(empty&&uvpaa)?'block':'none';
  document.getElementById('add-btn').style.display=empty?'none':'block';
}
async function deletePasskey(id){const st=document.getElementById('status');st.style.color='#b00';st.textContent='';if(!confirm('このパスキーを削除しますか？'))return;try{const r=await fetch('/api/v1/users/'+USER_ID+'/passkeys/'+id,{method:'DELETE'});if(!r.ok)throw new Error(await serverErrText(r,'削除に失敗'));st.style.color='#070';st.textContent='削除しました。';loadPasskeys();}catch(err){st.textContent='削除失敗: '+passkeyErr(err);}}
async function registerPasskey(){const st=document.getElementById('status');st.style.color='#b00';st.textContent='登録中...';try{const r=await fetch('/api/v1/users/'+USER_ID+'/passkeys/register/start',{method:'POST',headers:{'Accept':'application/json','content-type':'application/json'},body:'{}'});if(!r.ok)throw new Error(await serverErrText(r,'開始に失敗'));const d=await r.json();const pk=d.options.publicKey;pk.challenge=b64urlToBuf(pk.challenge);pk.user.id=b64urlToBuf(pk.user.id);(pk.excludeCredentials||[]).forEach(c=>c.id=b64urlToBuf(c.id));const cred=await navigator.credentials.create({publicKey:pk});const fr=await fetch('/api/v1/users/'+USER_ID+'/passkeys/register/finish',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({challenge_id:d.challenge_id,name:'My Passkey',credential:attestationJSON(cred)})});if(!fr.ok)throw new Error(await serverErrText(fr,'登録に失敗'));st.style.color='#070';st.textContent='パスキーを登録しました。';loadPasskeys();}catch(err){st.textContent='登録失敗: '+passkeyErr(err);}}
loadPasskeys();
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
    prompt: Option<&str>,
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
        .authorization_url_pkce_prompt(callback_url, &opaque_state, &nonce, Some(&pkce.challenge), prompt))
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
    jar: CookieJar,
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

    let (device_id, risk_ctx) = build_risk_context(&headers, &jar);
    if is_json_accept(&headers) {
        match complete_oidc(&state, &code, &flow, &risk_ctx).await {
            Ok((session_id, redirect_to)) => {
                let mut resp = Json(serde_json::json!({"redirect_to": redirect_to})).into_response();
                set_session_cookie(&mut resp, &session_id, &state);
                set_device_cookie(&mut resp, &device_id, &state);
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
        match complete_oidc(&state, &code, &flow, &risk_ctx).await {
            Ok((session_id, redirect_to)) => {
                let mut resp = Redirect::to(&redirect_to).into_response();
                set_session_cookie(&mut resp, &session_id, &state);
                set_device_cookie(&mut resp, &device_id, &state);
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
    headers: HeaderMap,
    jar: CookieJar,
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

    let (device_id, risk_ctx) = build_risk_context(&headers, &jar);
    match complete_oidc(&state, &code, &flow, &risk_ctx).await {
        Ok((session_id, redirect_to)) => {
            let mut resp = Redirect::to(&redirect_to).into_response();
            set_session_cookie(&mut resp, &session_id, &state);
            set_device_cookie(&mut resp, &device_id, &state);
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
    ctx: &RiskContext,
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

    // ── Account linking (Phase 5) ────────────────────────────
    // Resolve by (provider, subject). A new identity links to an existing user
    // iff its email is VERIFIED and matches — never auto-link an unverified
    // email (account-takeover guard). Otherwise a fresh user is created. Legacy
    // google users (google_sub set, no identity row) get back-filled here.
    let provider = state.idp.config().provider.clone();
    let email_verified = userinfo.email_verified.unwrap_or(false);
    let user = match UserIdentityStore::find_by_subject(&state.db, &provider, &sub).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
    {
        Some(idn) => UserStore::find_by_id(&state.db, idn.user_id).await
            .map_err(|e| ApiError::internal(&e.to_string()))?
            .ok_or_else(|| ApiError::internal("linked identity points to a missing user"))?,
        None => {
            let existing = if email_verified {
                UserStore::find_by_email(&state.db, &email).await
                    .map_err(|e| ApiError::internal(&e.to_string()))?
            } else { None };
            let user = match existing {
                Some(u) => u,
                None => UserStore::upsert(&state.db, volta_auth_core::record::UserRecord {
                    id: uuid::Uuid::new_v4(),
                    email: email.clone(),
                    display_name: userinfo.name.clone(),
                    google_sub: if provider == "google" { Some(sub.clone()) } else { None },
                    created_at: now,
                    is_active: true,
                    locale: None,
                    deleted_at: None,
                }).await.map_err(|e| ApiError::internal(&e.to_string()))?,
            };
            let _ = UserIdentityStore::link(&state.db, volta_auth_core::record::UserIdentityRecord {
                id: uuid::Uuid::new_v4(), user_id: user.id, provider: provider.clone(),
                subject: sub.clone(), email: Some(email.clone()), email_verified, created_at: now,
            }).await;
            user
        }
    };

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

    // ── Risk-based adaptive auth (Phase 4c) ──────────────────
    // Signals: a device we've never seen for this user, and a source IP that
    // differs from their most recent session. Fail-open — store/lookup errors
    // resolve to the low-risk interpretation, never a lock-out.
    let known = RiskDeviceStore::check_and_record(&state.db, user.id, &ctx.device_hash)
        .await.unwrap_or(true);
    let ip_changed = match &ctx.client_ip {
        Some(ip) => SessionStore::list_by_user(&state.db, &user.id.to_string()).await
            .ok().unwrap_or_default().into_iter()
            .max_by_key(|sess| sess.created_at)   // most recent prior session
            .and_then(|sess| sess.ip_address)
            .map(|prev| prev != *ip)
            .unwrap_or(false),
        None => false,
    };
    let signals = RiskSignals { new_device: !known, ip_changed, ..Default::default() };
    let (risk_level, decision) = risk::evaluate(&signals, &RiskThresholds::default(), 0);

    if decision == RiskDecision::Block {
        let mut ev = crate::auth_events::AuthEvent::now("LOGIN_BLOCKED").with_user(user.id.to_string());
        ev.detail = Some(serde_json::json!({ "risk_level": risk_level, "new_device": !known, "ip_changed": ip_changed }));
        state.auth_events.publish_and_audit(
            ev, &state.db, ctx.client_ip.clone(), Some("USER".into()), Some(user.id.to_string()), None,
        ).await;
        return Err(ApiError::forbidden("LOGIN_BLOCKED", "不審なアクセスを検知したためログインを拒否しました。時間をおくか、管理者にお問い合わせください。"));
    }

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
        // StepUp (risk ≥ action) leaves the session MFA-unverified so ForwardAuth
        // routes the user through /mfa/challenge when they have a second factor.
        mfa_verified_at: None,
        ip_address: ctx.client_ip.clone(),
        user_agent: ctx.user_agent.clone(),
        csrf_token: None,
        email: Some(email),
        tenant_slug,
        roles,
        display_name: user.display_name,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    // Risk step-up: flag the session so ForwardAuth requires a second factor
    // (TOTP or passkey) even if tenant policy wouldn't otherwise.
    if decision == RiskDecision::StepUp {
        let _ = SessionStepUpStore::mark(&state.db, &session_id).await;
    }

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
