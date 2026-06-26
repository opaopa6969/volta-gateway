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
use webauthn_rs::prelude::{DiscoverableKey, Passkey, PublicKeyCredential, RegisterPublicKeyCredential};

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

    // Per WebAuthn spec, signCount = 0 means the authenticator does not
    // implement a signature counter — platform authenticators (Windows Hello,
    // Touch ID) and synced passkeys commonly always report 0. Only treat a
    // non-advancing counter as a clone/replay when the authenticator actually
    // uses counters (returned value > 0); otherwise accept without the check.
    let new_counter = result.counter() as i64;
    if new_counter > 0 {
        let applied = PasskeyStore::update_counter(&s.db, passkey_row.id, new_counter)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        if !applied {
            return Err(ApiError::unauthorized(
                "PASSKEY_FAILED",
                "sign-counter rejected — possible replay or cloned authenticator",
            ));
        }
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

    s.auth_events.publish_and_audit(
        crate::auth_events::AuthEvent::now("LOGIN_SUCCESS")
            .with_user(passkey_row.user_id.to_string())
            .with_session(session_id.clone()),
        &s.db,
        None,
        Some("SESSION".into()),
        Some(session_id.clone()),
        None,
    ).await;

    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    set_session_cookie(&mut resp, &session_id, &s);
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ── discoverable-credential login (username-less) ─────────

/// POST /auth/passkey/discover/start — begin discoverable-credential login.
///
/// No body required. Returns a challenge with `allowCredentials=[]` and
/// `userVerification=required`. The authenticator presents all resident keys
/// it holds for this RP; the user picks one.
pub async fn discover_start(
    State(s): State<AppState>,
) -> Result<Response, ApiError> {
    let svc = service(&s)?;

    let (challenge, state) = svc
        .start_discoverable_authentication()
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    // No user_id yet — we don't know who is logging in until finish.
    let challenge_id = persist_challenge(&s, None, "discover", &state).await?;

    let mut resp = Json(serde_json::json!({
        "challenge_id": challenge_id,
        "options": challenge,
    }))
    .into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[derive(Deserialize)]
pub struct DiscoverFinishReq {
    pub challenge_id: Uuid,
    pub credential: PublicKeyCredential,
}

/// POST /auth/passkey/discover/finish — verify discoverable-credential assertion + issue session.
///
/// `credential` must contain a `userHandle` (user_unique_id) so the server can
/// look up the user and their passkeys without requiring an email input.
pub async fn discover_finish(
    State(s): State<AppState>,
    Json(req): Json<DiscoverFinishReq>,
) -> Result<Response, ApiError> {
    let svc = service(&s)?;

    let record = PasskeyChallengeStore::consume(&s.db, req.challenge_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("INVALID_CHALLENGE", "unknown or expired challenge"))?;
    if record.kind != "discover" {
        return Err(ApiError::bad_request("INVALID_CHALLENGE", "wrong ceremony kind"));
    }
    let discover_state = decode_state(&record.state)?;

    // Extract the user_unique_id from the credential's userHandle.
    let (user_unique_id, _cred_id_bytes) = svc
        .identify_discoverable_authentication(&req.credential)
        .map_err(|_| ApiError::unauthorized("PASSKEY_FAILED", "missing or invalid userHandle in credential"))?;

    // Load the user and their passkeys by user_unique_id (== user.id).
    let user = UserStore::find_by_id(&s.db, user_unique_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("PASSKEY_FAILED", "no matching credential"))?;

    let records = PasskeyStore::list_by_user(&s.db, user.id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let passkeys = passkeys_from_records(&records)?;
    if passkeys.is_empty() {
        return Err(ApiError::unauthorized("PASSKEY_FAILED", "no matching credential"));
    }
    let discoverable_keys: Vec<DiscoverableKey> = passkeys.iter().map(DiscoverableKey::from).collect();

    let result = svc
        .finish_discoverable_authentication(&req.credential, discover_state, &discoverable_keys)
        .map_err(|_| ApiError::unauthorized("PASSKEY_FAILED", "assertion verification failed"))?;

    // Update atomic sign counter (clone-detection, same as username-bound flow).
    let cred_id_bytes: &[u8] = result.cred_id().as_ref();
    let passkey_row = PasskeyStore::find_by_credential_id(&s.db, cred_id_bytes)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("PASSKEY_FAILED", "credential not on file"))?;

    // Per WebAuthn spec, signCount = 0 means the authenticator does not
    // implement a signature counter — platform authenticators (Windows Hello,
    // Touch ID) and synced passkeys commonly always report 0. Only treat a
    // non-advancing counter as a clone/replay when the authenticator actually
    // uses counters (returned value > 0); otherwise accept without the check.
    let new_counter = result.counter() as i64;
    if new_counter > 0 {
        let applied = PasskeyStore::update_counter(&s.db, passkey_row.id, new_counter)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
        if !applied {
            return Err(ApiError::unauthorized(
                "PASSKEY_FAILED",
                "sign-counter rejected — possible replay or cloned authenticator",
            ));
        }
    }

    // Issue a session (passkey = MFA-equivalent; set mfa_verified_at).
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

    s.auth_events.publish_and_audit(
        crate::auth_events::AuthEvent::now("LOGIN_SUCCESS")
            .with_user(passkey_row.user_id.to_string())
            .with_session(session_id.clone()),
        &s.db,
        None,
        Some("SESSION".into()),
        Some(session_id.clone()),
        None,
    ).await;

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

    // serde_json, not bincode: webauthn-rs's Passkey uses serde `deserialize_any`
    // (untagged/flatten), which bincode (non-self-describing) cannot read back —
    // it serializes fine but `bincode::deserialize::<Passkey>` then fails at login
    // with "Bincode does not support deserialize_any". JSON round-trips cleanly.
    let pub_key_bytes = serde_json::to_vec(&passkey)
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
    // serde_json, not bincode: webauthn-rs's PasskeyRegistration state contains
    // variable-size maps (extensions) that bincode cannot encode
    // ("...sequences and maps that have a knowable size ahead of time"). JSON
    // handles them; challenges are transient so the on-disk format is internal.
    let bytes = serde_json::to_vec(state)
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
    serde_json::from_slice(bytes)
        .map_err(|e| ApiError::internal(&format!("passkey state deserialize: {}", e)))
}

fn passkeys_from_records(records: &[volta_auth_core::record::PasskeyRecord]) -> Result<Vec<Passkey>, ApiError> {
    // Skip (rather than hard-fail on) any record we can't decode, so one
    // unreadable credential never bricks a user's whole passkey set. Legacy
    // bincode-encoded rows are unreadable as JSON and get dropped here.
    Ok(records
        .iter()
        .filter_map(|r| match serde_json::from_slice::<Passkey>(&r.public_key) {
            Ok(pk) => Some(pk),
            Err(e) => {
                tracing::warn!(error = %e, "skipping undecodable passkey record");
                None
            }
        })
        .collect())
}
