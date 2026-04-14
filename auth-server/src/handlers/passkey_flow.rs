//! Passkey authentication + registration handlers.
//!
//! Backlog P1 #5: real webauthn-rs ceremony lifecycle. See
//! `auth-server/docs/specs/passkey-webauthn-integration.md`.
//!
//! State between start and finish lives in `passkey_challenges` (server-side,
//! atomic single-use).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential};

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{extract_session_id, set_session_cookie};
use crate::state::AppState;
use volta_auth_core::store::{PasskeyChallengeRecord, PasskeyChallengeStore, PasskeyStore, SessionStore, UserStore};

/// Challenge TTL — same as OIDC flow TTL. WebAuthn spec suggests ≤5 minutes.
const CHALLENGE_TTL_SECS: i64 = 300;

fn service(s: &AppState) -> Result<&volta_auth_core::passkey::PasskeyService, ApiError> {
    s.passkey.as_deref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "PASSKEY_DISABLED",
            "passkey not configured — set WEBAUTHN_RP_ID and WEBAUTHN_RP_ORIGIN",
        )
    })
}

// ── login (authentication) ────────────────────────────────

#[derive(Deserialize)]
pub struct AuthStartReq {
    pub email: Option<String>,
}

/// POST /auth/passkey/start — begin passkey login.
///
/// Non-discoverable flow: client submits `email`, server loads that user's
/// passkeys and produces a challenge bound to them. Discoverable-credential
/// support is a P2 follow-up (no email needed).
pub async fn auth_start(
    State(s): State<AppState>,
    Json(req): Json<AuthStartReq>,
) -> Result<Response, ApiError> {
    let svc = service(&s)?;
    let email = req
        .email
        .as_deref()
        .map(crate::security::normalize_email)
        .filter(|e| !e.is_empty())
        .ok_or_else(|| ApiError::bad_request("BAD_REQUEST", "email required"))?;

    let user = UserStore::find_by_email(&s.db, &email)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("PASSKEY_FAILED", "no matching credential"))?;

    let records = PasskeyStore::list_by_user(&s.db, user.id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let credentials = passkeys_from_records(&records)?;
    if credentials.is_empty() {
        return Err(ApiError::unauthorized("PASSKEY_FAILED", "no matching credential"));
    }

    let (challenge, state) = svc
        .start_authentication(&credentials)
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let challenge_id = persist_challenge(&s, Some(user.id), "auth", &state).await?;

    let mut resp = Json(serde_json::json!({
        "challenge_id": challenge_id,
        "options": challenge,
    }))
    .into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[derive(Deserialize)]
pub struct AuthFinishReq {
    pub challenge_id: Uuid,
    pub credential: PublicKeyCredential,
}

/// POST /auth/passkey/finish — verify assertion + issue session.
pub async fn auth_finish(
    State(s): State<AppState>,
    Json(req): Json<AuthFinishReq>,
) -> Result<Response, ApiError> {
    let svc = service(&s)?;

    let record = PasskeyChallengeStore::consume(&s.db, req.challenge_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("INVALID_CHALLENGE", "unknown or expired challenge"))?;
    if record.kind != "auth" {
        return Err(ApiError::bad_request("INVALID_CHALLENGE", "wrong ceremony kind"));
    }
    let auth_state = decode_state(&record.state)?;

    let result = svc
        .finish_authentication(&req.credential, &auth_state)
        .map_err(|_| ApiError::unauthorized("PASSKEY_FAILED", "assertion verification failed"))?;

    // Update atomic sign counter (issue #17). We look up by credential_id
    // from the authentication result.
    let cred_id_bytes: &[u8] = result.cred_id().as_ref();
    let passkey_row = PasskeyStore::find_by_credential_id(&s.db, cred_id_bytes)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("PASSKEY_FAILED", "credential not on file"))?;

    let applied = PasskeyStore::update_counter(&s.db, passkey_row.id, result.counter() as i64)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    if !applied {
        return Err(ApiError::unauthorized(
            "PASSKEY_FAILED",
            "sign-counter rejected — possible replay or cloned authenticator",
        ));
    }

    // Issue a session. `mfa_verified_at = Some(...)` because passkey is an
    // MFA-equivalent authenticator (user verification already performed).
    let session_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SessionStore::create(
        &s.db,
        volta_auth_core::record::SessionRecord {
            session_id: session_id.clone(),
            user_id: passkey_row.user_id.to_string(),
            tenant_id: String::new(),
            return_to: None,
            created_at: now,
            last_active_at: now,
            expires_at: now + s.session_ttl_secs,
            invalidated_at: None,
            mfa_verified_at: Some(now),
            ip_address: None,
            user_agent: None,
            csrf_token: None,
            email: None,
            tenant_slug: None,
            roles: vec![],
            display_name: None,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    s.auth_events.publish(
        crate::auth_events::AuthEvent::now("LOGIN_SUCCESS")
            .with_user(passkey_row.user_id.to_string())
            .with_session(session_id.clone()),
    );

    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    set_session_cookie(&mut resp, &session_id, &s);
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ── registration ──────────────────────────────────────────

/// POST /api/v1/users/{userId}/passkeys/register/start
pub async fn register_start(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(uid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let svc = service(&s)?;
    let sid = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let session = SessionStore::find(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    // A user may only register passkeys for themselves.
    if session.user_id != uid.to_string() {
        return Err(ApiError::forbidden("FORBIDDEN", "cannot register for another user"));
    }

    let user = UserStore::find_by_id(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "user not found"))?;

    let existing = PasskeyStore::list_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let existing_ids: Vec<_> = existing
        .iter()
        .map(|p| webauthn_rs::prelude::CredentialID::from(p.credential_id.clone()))
        .collect();

    let (challenge, state) = svc
        .start_registration(
            uid,
            &user.email,
            user.display_name.as_deref().unwrap_or(&user.email),
            if existing_ids.is_empty() { None } else { Some(existing_ids) },
        )
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let challenge_id = persist_challenge(&s, Some(uid), "register", &state).await?;

    let mut resp = Json(serde_json::json!({
        "challenge_id": challenge_id,
        "options": challenge,
    }))
    .into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    pub challenge_id: Uuid,
    pub name: Option<String>,
    pub credential: RegisterPublicKeyCredential,
}

/// POST /api/v1/users/{userId}/passkeys/register/finish
pub async fn register_finish(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(uid): Path<Uuid>,
    Json(req): Json<RegisterFinishReq>,
) -> Result<Response, ApiError> {
    let svc = service(&s)?;
    let sid = extract_session_id(&jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let session = SessionStore::find(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    if session.user_id != uid.to_string() {
        return Err(ApiError::forbidden("FORBIDDEN", "cannot register for another user"));
    }

    let record = PasskeyChallengeStore::consume(&s.db, req.challenge_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("INVALID_CHALLENGE", "unknown or expired challenge"))?;
    if record.kind != "register" || record.user_id != Some(uid) {
        return Err(ApiError::bad_request("INVALID_CHALLENGE", "mismatched challenge"));
    }
    let reg_state = decode_state(&record.state)?;

    let passkey = svc
        .finish_registration(&req.credential, &reg_state)
        .map_err(|e| ApiError::bad_request("PASSKEY_FAILED", &format!("registration failed: {}", e)))?;

    let pub_key_bytes = bincode::serialize(&passkey)
        .map_err(|e| ApiError::internal(&format!("passkey serialize: {}", e)))?;

    PasskeyStore::create(
        &s.db,
        volta_auth_core::record::PasskeyRecord {
            id: Uuid::new_v4(),
            user_id: uid,
            credential_id: passkey.cred_id().as_ref().to_vec(),
            public_key: pub_key_bytes,
            sign_count: 0,
            transports: None,
            name: req.name.or_else(|| Some("My Passkey".into())),
            aaguid: None,
            backup_eligible: false,
            backup_state: false,
            created_at: chrono::Utc::now(),
            last_used_at: None,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ── helpers ───────────────────────────────────────────────

async fn persist_challenge<T: serde::Serialize>(
    s: &AppState,
    user_id: Option<Uuid>,
    kind: &str,
    state: &T,
) -> Result<Uuid, ApiError> {
    let bytes = bincode::serialize(state)
        .map_err(|e| ApiError::internal(&format!("passkey state serialize: {}", e)))?;
    let id = Uuid::new_v4();
    let expires = chrono::Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECS);
    PasskeyChallengeStore::save(
        &s.db,
        PasskeyChallengeRecord {
            id,
            user_id,
            state: bytes,
            kind: kind.into(),
            created_at: chrono::Utc::now(),
            expires_at: expires,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(id)
}

fn decode_state<T: for<'de> serde::Deserialize<'de>>(bytes: &[u8]) -> Result<T, ApiError> {
    bincode::deserialize(bytes)
        .map_err(|e| ApiError::internal(&format!("passkey state deserialize: {}", e)))
}

fn passkeys_from_records(records: &[volta_auth_core::record::PasskeyRecord]) -> Result<Vec<Passkey>, ApiError> {
    records
        .iter()
        .map(|r| {
            bincode::deserialize::<Passkey>(&r.public_key)
                .map_err(|e| ApiError::internal(&format!("passkey deserialize: {}", e)))
        })
        .collect()
}
