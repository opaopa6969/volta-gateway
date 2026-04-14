//! MFA handlers — setup, verify, disable, recovery codes, challenge.
//! 100% compatible with Java volta-auth-proxy.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{extract_session_id, set_session_cookie};
use crate::state::AppState;
use volta_auth_core::store::{SessionStore, MfaStore, RecoveryCodeStore};
use volta_auth_core::totp;

/// GET /mfa/challenge — TOTP input page (AUTH-010 `99a2769`).
///
/// Requires an active session (otherwise redirects to /login). The session
/// does NOT need `mfa_verified_at` set — that's the whole point of this page.
pub async fn mfa_challenge(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Response {
    let session_id = match extract_session_id(&jar) {
        Some(id) => id,
        None => {
            let mut resp = axum::response::Redirect::to(&format!("{}/login", state.base_url)).into_response();
            no_cache_headers(&mut resp);
            return resp;
        }
    };
    // Verify the session actually exists — if it was revoked, send the user back
    // to /login rather than showing a phantom MFA page.
    match SessionStore::find(&state.db, &session_id).await {
        Ok(Some(_)) => {}
        _ => {
            let mut resp = axum::response::Redirect::to(&format!("{}/login", state.base_url)).into_response();
            no_cache_headers(&mut resp);
            return resp;
        }
    }

    // Minimal Java-compat HTML; real UI lives in volta-auth-console.
    let html = r##"<!DOCTYPE html><html lang="ja"><head>
<meta charset="utf-8"><title>MFA Challenge — volta</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);max-width:360px;width:100%}
h1{margin:0 0 8px;font-size:20px}
p{color:#666;margin:0 0 24px;font-size:14px}
input{width:100%;padding:12px;border:1px solid #ddd;border-radius:6px;font-size:16px;box-sizing:border-box;margin-bottom:12px;letter-spacing:2px;text-align:center}
button{width:100%;padding:12px;background:#0f3460;color:#fff;border:0;border-radius:6px;font-size:16px;cursor:pointer}
button:hover{background:#16213e}
.err{color:#c62828;font-size:13px;min-height:18px;margin-top:8px}
</style></head><body>
<form class="card" id="f">
  <h1>多要素認証</h1>
  <p>認証アプリに表示される 6 桁のコード、または recovery code を入力してください。</p>
  <input name="code" inputmode="numeric" autocomplete="one-time-code" autofocus required>
  <button type="submit">確認</button>
  <div class="err" id="e"></div>
</form>
<script>
const f = document.getElementById('f'), e = document.getElementById('e');
f.addEventListener('submit', async ev => {
  ev.preventDefault();
  e.textContent = '';
  const code = new FormData(f).get('code');
  const r = await fetch('/auth/mfa/verify', {
    method: 'POST',
    headers: {'Content-Type':'application/json','Accept':'application/json'},
    credentials: 'include',
    body: JSON.stringify({code}),
  });
  if (r.ok) { location.replace(new URLSearchParams(location.search).get('return_to') || '/'); return; }
  try { const j = await r.json(); e.textContent = j.message || 'コードが正しくありません'; }
  catch { e.textContent = 'コードが正しくありません'; }
});
</script></body></html>"##;
    let mut resp = Html(html).into_response();
    no_cache_headers(&mut resp);
    resp
}

/// POST /api/v1/users/{userId}/mfa/totp/setup — generate TOTP secret.
pub async fn totp_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, ApiError> {
    let _session = verify_session(&state, &jar).await?;

    let secret = totp::generate_secret();
    let uri = format!(
        "otpauth://totp/volta:{}?secret={}&issuer=volta",
        user_id, secret
    );

    // Store (inactive until verified)
    MfaStore::upsert(&state.db, user_id, "totp", &secret).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    // Immediately deactivate — will activate on verify
    MfaStore::deactivate(&state.db, user_id, "totp").await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({
        "secret": secret,
        "uri": uri,
    })).into_response())
}

#[derive(Deserialize)]
pub struct VerifyCode {
    pub code: String,
}

/// POST /api/v1/users/{userId}/mfa/totp/verify — verify TOTP during setup.
pub async fn totp_verify_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(user_id): Path<uuid::Uuid>,
    Json(body): Json<VerifyCode>,
) -> Result<Response, ApiError> {
    let _session = verify_session(&state, &jar).await?;

    // Find the MFA record (even inactive, since we just set it up)
    let mfa = sqlx::query_as::<_, volta_auth_core::record::MfaRecord>(
        "SELECT id, user_id, type AS mfa_type, secret, is_active, created_at \
         FROM user_mfa WHERE user_id = $1 AND type = 'totp'"
    )
    .bind(user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?
    .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "TOTP not set up"))?;

    let valid = totp::verify_totp(mfa.secret.as_bytes(), &body.code, 30);
    if !valid {
        return Err(ApiError::bad_request("INVALID_CODE", "Invalid TOTP code"));
    }

    // Activate
    MfaStore::upsert(&state.db, user_id, "totp", &mfa.secret).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    // Generate recovery codes
    let codes = generate_recovery_codes(10);
    let hashes: Vec<String> = codes.iter().map(|c| sha256_hex(c)).collect();
    RecoveryCodeStore::replace_all(&state.db, user_id, &hashes).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({
        "ok": true,
        "recovery_codes": codes,
    })).into_response())
}

/// DELETE /api/v1/users/{userId}/mfa/totp — disable TOTP.
pub async fn totp_disable(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, ApiError> {
    let _session = verify_session(&state, &jar).await?;

    MfaStore::deactivate(&state.db, user_id, "totp").await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    RecoveryCodeStore::delete_all(&state.db, user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

/// GET /api/v1/users/me/mfa — MFA status.
pub async fn mfa_status(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session = verify_session(&state, &jar).await?;
    let user_id: uuid::Uuid = session.user_id.parse()
        .map_err(|_| ApiError::internal("invalid user_id"))?;

    let has_mfa = MfaStore::has_active(&state.db, user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let recovery_count = if has_mfa {
        RecoveryCodeStore::count_unused(&state.db, user_id).await
            .map_err(|e| ApiError::internal(&e.to_string()))?
    } else { 0 };

    let mfa_type: serde_json::Value = if has_mfa {
        serde_json::Value::String("totp".into())
    } else {
        serde_json::Value::Null
    };

    Ok(Json(serde_json::json!({
        "enabled": has_mfa,
        "type": mfa_type,
        "recovery_codes_remaining": recovery_count,
    })).into_response())
}

/// POST /api/v1/users/{userId}/mfa/recovery-codes/regenerate
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Response, ApiError> {
    let _session = verify_session(&state, &jar).await?;

    let codes = generate_recovery_codes(10);
    let hashes: Vec<String> = codes.iter().map(|c| sha256_hex(c)).collect();
    RecoveryCodeStore::replace_all(&state.db, user_id, &hashes).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({
        "recovery_codes": codes,
    })).into_response())
}

/// POST /auth/mfa/verify — verify TOTP code during login.
pub async fn mfa_verify_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<VerifyCode>,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let session = SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;

    let user_id: uuid::Uuid = session.user_id.parse()
        .map_err(|_| ApiError::internal("invalid user_id"))?;

    let mfa = MfaStore::find(&state.db, user_id, "totp").await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("MFA_REQUIRED", "MFA not configured"))?;

    let valid = totp::verify_totp(mfa.secret.as_bytes(), &body.code, 30);
    if !valid {
        // Try recovery code
        let hash = sha256_hex(&body.code);
        let consumed = RecoveryCodeStore::consume(&state.db, user_id, &hash).await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        if !consumed {
            return Err(ApiError::unauthorized("MFA_FAILED", "MFA verification failed"));
        }
    }

    // Mark session MFA verified
    SessionStore::mark_mfa_verified(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    set_session_cookie(&mut resp, &session_id, &state);
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ─── Helpers ───────────────────────────────────────────────

use volta_auth_core::record::SessionRecord;

async fn verify_session(state: &AppState, jar: &CookieJar) -> Result<SessionRecord, ApiError> {
    let session_id = extract_session_id(jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;
    SessionStore::find(&state.db, &session_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))
}

fn generate_recovery_codes(count: usize) -> Vec<String> {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    (0..count).map(|_| {
        let mut bytes = [0u8; 4];
        rng.fill(&mut bytes).unwrap();
        format!("{:08x}", u32::from_be_bytes(bytes))
    }).collect()
}

pub fn sha256_hex_pub(input: &str) -> String { sha256_hex(input) }

fn sha256_hex(input: &str) -> String {
    use sha2::{Sha256, Digest};
    let hash = Sha256::digest(input.as_bytes());
    hex::encode(hash)
}
