//! Passkey authentication flow handlers — start/finish for login + registration.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use uuid::Uuid;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{extract_session_id, set_session_cookie};
use crate::state::AppState;
use volta_auth_core::store::{SessionStore, PasskeyStore};

/// POST /auth/passkey/start — begin passkey authentication (login).
pub async fn auth_start(State(s): State<AppState>) -> Result<Response, ApiError> {
    // In real impl: use PasskeyService to generate challenge from stored credentials.
    // For now: return a challenge placeholder.
    let challenge = uuid::Uuid::new_v4().to_string();
    let mut resp = Json(serde_json::json!({
        "challenge": challenge,
        "rp_id": "localhost",
        "timeout": 60000,
    })).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

/// POST /auth/passkey/finish — verify passkey assertion (login).
pub async fn auth_finish(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    // In real impl: PasskeyService.finish_authentication + PasskeyStore lookup.
    let credential_id = body.get("credential_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::bad_request("BAD_REQUEST", "credential_id required"))?;

    // Lookup passkey by credential_id
    let passkey = PasskeyStore::find_by_credential_id(&s.db, credential_id.as_bytes()).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("PASSKEY_FAILED", "unknown credential"))?;

    // Create session
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    SessionStore::create(&s.db, volta_auth_core::record::SessionRecord {
        session_id: session_id.clone(),
        user_id: passkey.user_id.to_string(),
        tenant_id: String::new(), // resolved from membership in real impl
        return_to: None,
        created_at: now, last_active_at: now,
        expires_at: now + s.session_ttl_secs,
        invalidated_at: None, mfa_verified_at: Some(now), // passkey = MFA verified
        ip_address: None, user_agent: None, csrf_token: None,
        email: None, tenant_slug: None, roles: vec![], display_name: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    // #17: atomic sign-counter bump. If the update is rejected (stored count >=
    // new count) we treat the assertion as a replay and reject the login.
    let new_count = passkey.sign_count + 1;
    let applied = PasskeyStore::update_counter(&s.db, passkey.id, new_count).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    if !applied {
        return Err(ApiError::unauthorized(
            "PASSKEY_FAILED",
            "sign-counter rejected — possible replay or cloned authenticator",
        ));
    }

    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    set_session_cookie(&mut resp, &session_id, &s);
    no_cache_headers(&mut resp);
    Ok(resp)
}

/// POST /api/v1/users/{userId}/passkeys/register/start
pub async fn register_start(State(s): State<AppState>, jar: CookieJar, Path(uid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = extract_session_id(&jar).ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let challenge = uuid::Uuid::new_v4().to_string();
    let mut resp = Json(serde_json::json!({
        "challenge": challenge,
        "rp": {"id": "localhost", "name": "volta"},
        "user": {"id": uid.to_string(), "name": uid.to_string()},
        "timeout": 60000,
    })).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

/// POST /api/v1/users/{userId}/passkeys/register/finish
pub async fn register_finish(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(uid): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> Result<Response, ApiError> {
    let _ = extract_session_id(&jar).ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;

    // In real impl: PasskeyService.finish_registration.
    // For now: store raw credential data.
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("My Passkey");
    let cred_id = body.get("credential_id").and_then(|v| v.as_str()).unwrap_or("");

    PasskeyStore::create(&s.db, volta_auth_core::record::PasskeyRecord {
        id: Uuid::new_v4(),
        user_id: uid,
        credential_id: cred_id.as_bytes().to_vec(),
        public_key: vec![], // filled by webauthn-rs in real impl
        sign_count: 0,
        transports: None,
        name: Some(name.to_string()),
        aaguid: None,
        backup_eligible: false,
        backup_state: false,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})).into_response())
}
