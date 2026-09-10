//! Passwordless registration endpoints (Phase 2). Thin HTTP layer over
//! `volta_auth_core::runtime`. Responses carry the flow state + next actions so
//! the client knows what to do next. No account-enumeration leaks: verify and
//! resend return generic responses regardless of whether the address exists.

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use volta_auth_core::runtime;

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct StartReq {
    pub email: String,
}

/// GET /register — browser UI for the existing passwordless registration API.
///
/// The verification value is intentionally entered by the user rather than
/// embedded in a URL. This keeps a mailbox token out of browser history,
/// referrer headers, and access logs.
pub async fn registration_page() -> Response {
    let mut response = Html(REGISTRATION_PAGE).into_response();
    crate::error::no_cache_headers(&mut response);
    response
}

const REGISTRATION_PAGE: &str = r#"<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>アカウントを作成 — Volta Auth</title><style>body{font-family:system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem;text-align:center}h1{font-size:1.3rem}.field{width:100%;padding:.75rem;margin:.4rem 0;border:1px solid #ccc;border-radius:8px;box-sizing:border-box;font-size:1rem}.btn{display:block;width:100%;padding:.8rem;margin:.6rem 0;border:1px solid #ccc;border-radius:8px;background:#fff;font-size:1rem;cursor:pointer;text-decoration:none;color:#222;box-sizing:border-box}.btn.primary{background:#4285f4;color:#fff;border-color:#4285f4}.hint{color:#555;font-size:.9rem;line-height:1.5;text-align:left}.hidden{display:none}#status{margin-top:1rem;min-height:1.4em;font-size:.9rem}</style></head><body><h1>アカウントを作成</h1><p class="hint">メールアドレスを入力すると確認メールを送ります。メール内の確認コードをここに貼り付けてください。</p><form id="start-form"><input class="field" id="email" type="email" autocomplete="email" required placeholder="メールアドレス"><button class="btn primary" type="submit">確認メールを送る</button></form><section id="verify" class="hidden"><p class="hint">確認メールに記載されたコードを入力してください。</p><form id="verify-form"><input class="field" id="token" type="text" autocomplete="one-time-code" required placeholder="確認コード"><button class="btn primary" type="submit">メールアドレスを確認</button></form><button class="btn" id="resend" type="button">確認メールを再送する</button></section><p id="status" role="status"></p><a class="btn" href="/login">ログインに戻る</a><script>const status=document.getElementById('status');let registeredEmail='';function message(text,ok){status.textContent=text;status.style.color=ok?'#070':'#b00';}async function api(path,body){const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json','accept':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw new Error('処理に失敗しました。入力内容を確認して、もう一度お試しください。');return r.json();}document.getElementById('start-form').addEventListener('submit',async e=>{e.preventDefault();registeredEmail=document.getElementById('email').value.trim();if(!registeredEmail)return;message('送信中…');try{await api('/auth/register/start',{email:registeredEmail});document.getElementById('verify').classList.remove('hidden');message('確認メールを送信しました。メール内のコードを入力してください。',true);document.getElementById('token').focus();}catch(err){message(err.message);}});document.getElementById('verify-form').addEventListener('submit',async e=>{e.preventDefault();const token=document.getElementById('token').value.trim();if(!token)return;message('確認中…');try{await api('/auth/register/verify-email',{token});message('アカウントを作成しました。ログインしてください。',true);setTimeout(()=>{location.href='/login';},1200);}catch(err){message('確認コードが無効または期限切れです。');}});document.getElementById('resend').addEventListener('click',async()=>{if(!registeredEmail){message('先にメールアドレスを入力してください。');return;}message('再送中…');try{await api('/auth/register/resend-verification',{email:registeredEmail});message('確認メールを再送しました。',true);}catch(err){message(err.message);}});</script></body></html>"#;

/// POST /auth/register/start
pub async fn register_start(
    State(s): State<AppState>,
    Json(req): Json<StartReq>,
) -> Result<Response, ApiError> {
    let res = runtime::start_registration(
        &s.db,
        &req.email,
        s.email_verification_enabled,
        &s.notify_channel,
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut body = serde_json::json!({
        "flowId": res.outcome.flow_id,
        "state": res.outcome.state,
        "nextActions": res.outcome.next_actions,
    });
    // Dev/test convenience only — NEVER enable in production. Lets local flows
    // complete without a mailbox.
    if std::env::var("AUTH_EXPOSE_DEV_TOKEN").ok().as_deref() == Some("true") {
        if let Some(t) = res.dev_token {
            body["devToken"] = serde_json::json!(t);
        }
    }
    Ok(Json(body).into_response())
}

#[derive(Deserialize)]
pub struct VerifyReq {
    pub token: String,
}

/// POST /auth/register/verify-email
pub async fn register_verify_email(
    State(s): State<AppState>,
    Json(req): Json<VerifyReq>,
) -> Result<Response, ApiError> {
    let outcome = runtime::verify_email(&s.db, &req.token)
        .await
        // Generic error — do not reveal whether the token/flow existed.
        .map_err(|_| {
            ApiError::bad_request("INVALID_TOKEN", "invalid or expired verification token")
        })?;
    Ok(Json(serde_json::json!({
        "flowId": outcome.flow_id,
        "state": outcome.state,
        "nextActions": outcome.next_actions,
    }))
    .into_response())
}

#[derive(Deserialize)]
pub struct ResendReq {
    pub email: String,
}

/// POST /auth/register/resend-verification
pub async fn register_resend(
    State(s): State<AppState>,
    Json(req): Json<ResendReq>,
) -> Result<Response, ApiError> {
    // Best-effort; throttling + existence are handled inside. The response is
    // identical regardless of outcome to avoid account enumeration.
    let _ = runtime::resend_verification(&s.db, &req.email, &s.notify_channel, 60)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "If the address is pending verification, a new email has been sent."
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::REGISTRATION_PAGE;

    #[test]
    fn registration_page_uses_only_the_public_registration_endpoints() {
        for endpoint in [
            "/auth/register/start",
            "/auth/register/verify-email",
            "/auth/register/resend-verification",
        ] {
            assert!(REGISTRATION_PAGE.contains(endpoint));
        }
        assert!(REGISTRATION_PAGE.contains("/login"));
    }
}
