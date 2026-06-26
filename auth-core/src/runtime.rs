//! Passwordless registration / email-verification runtime (Phase 2).
//!
//! Ties together the tramli flow record (auth_flows), the hashed email
//! verification token, and the notification outbox. The flow record tracks the
//! lifecycle state; the token store holds the secret material; the notification
//! job is the (later-delivered) side effect.
//!
//! Passwordless decision (design §7-1): no password is set during registration.
//! Email verification → account is considered verified; MFA setup is optional
//! (default skip) so verification completes the flow. PasswordReset is not wired.

use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::crypto::{random_numeric_code, random_token_hex, sha256_hex};
use crate::error::AuthError;
use crate::record::FlowRecord;
use crate::store::{
    ChallengeVerifyOutcome, EmailVerificationTokenStore, FlowPersistence, LoginChallengeStore,
    NotificationJobStore,
};

pub const FLOW_TYPE: &str = "registration";
const TOKEN_TTL_MINUTES: i64 = 15;
const VERIFICATION_TEMPLATE: &str = "email-verification";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationOutcome {
    pub flow_id: Uuid,
    pub state: String,
    pub next_actions: Vec<String>,
}

/// `dev_token` is the raw verification token, returned ONLY so local/dev/test
/// can complete without a mailbox. It is never retrievable afterwards (only its
/// hash is persisted); production relies on the enqueued notification.
pub struct StartResult {
    pub outcome: RegistrationOutcome,
    pub dev_token: Option<String>,
}

fn next_actions(state: &str) -> Vec<String> {
    match state {
        "EmailVerificationPending" => {
            vec!["VERIFY_EMAIL".into(), "RESEND_VERIFICATION".into()]
        }
        "EmailVerified" => vec!["COMPLETE".into()],
        "MfaSetupOptional" => vec!["SETUP_MFA".into(), "SKIP_MFA".into()],
        _ => vec![], // Completed / Cancelled — terminal
    }
}

/// Begin registration. When `email_verification_enabled`, issues a hashed token
/// and enqueues a verification notification; otherwise marks the email verified
/// straight away (config-gated path).
pub async fn start_registration<S>(
    store: &S,
    email: &str,
    email_verification_enabled: bool,
    channel: &str,
) -> Result<StartResult, AuthError>
where
    S: FlowPersistence + EmailVerificationTokenStore + NotificationJobStore,
{
    let flow_id = Uuid::new_v4();
    let now = Utc::now();
    let state = if email_verification_enabled {
        "EmailVerificationPending"
    } else {
        "EmailVerified"
    };

    store
        .create(FlowRecord {
            id: flow_id,
            session_id: format!("reg:{}", flow_id),
            flow_type: FLOW_TYPE.into(),
            current_state: state.into(),
            guard_failure_count: 0,
            version: 0,
            created_at: now,
            updated_at: now,
            expires_at: now + Duration::hours(1),
            completed_at: None,
            exit_state: None,
            summary: None,
        })
        .await?;

    let mut dev_token = None;
    if email_verification_enabled {
        let raw = random_token_hex(32);
        store
            .issue(email, &sha256_hex(&raw), TOKEN_TTL_MINUTES, Some(flow_id))
            .await?;
        // The email body needs the raw token (the link). The job row is
        // transient; long-term only the hash lives in the token row.
        let payload = serde_json::json!({ "flow_id": flow_id, "token": raw });
        let corr = format!("{}:verify-send", flow_id);
        store
            .enqueue(channel, email, VERIFICATION_TEMPLATE, payload, Some(&corr))
            .await?;
        store
            .record_transition(flow_id, Some("Start"), state, "RegIssueVerification", None)
            .await?;
        dev_token = Some(raw);
    } else {
        store
            .record_transition(flow_id, Some("Start"), state, "verification_disabled", None)
            .await?;
    }

    Ok(StartResult {
        outcome: RegistrationOutcome {
            flow_id,
            state: state.into(),
            next_actions: next_actions(state),
        },
        dev_token,
    })
}

/// Verify the email token and complete registration (passwordless; MFA optional
/// → default skip). Invalid / expired / already-used token → `NotFound`.
pub async fn verify_email<S>(store: &S, raw_token: &str) -> Result<RegistrationOutcome, AuthError>
where
    S: FlowPersistence + EmailVerificationTokenStore,
{
    let rec = store
        .consume(&sha256_hex(raw_token))
        .await?
        .ok_or_else(|| AuthError::NotFound("invalid or expired verification token".into()))?;
    let flow_id = rec
        .flow_id
        .ok_or_else(|| AuthError::Internal("verification token has no flow".into()))?;
    let flow = store
        .find(flow_id)
        .await?
        .ok_or_else(|| AuthError::NotFound("registration flow not found".into()))?;

    // EmailVerificationPending → EmailVerified → (skip MFA) → Completed.
    store
        .update_state(flow_id, "Completed", flow.version + 1)
        .await?;
    store
        .record_transition(flow_id, Some(&flow.current_state), "EmailVerified", "RegVerifyEmailGuard", None)
        .await?;
    store
        .record_transition(flow_id, Some("EmailVerified"), "Completed", "branch(skip)", None)
        .await?;
    store
        .complete(flow_id, "Completed", Some(serde_json::json!({ "email": rec.email })))
        .await?;

    Ok(RegistrationOutcome {
        flow_id,
        state: "Completed".into(),
        next_actions: next_actions("Completed"),
    })
}

/// Re-send the verification email if outside the throttle window. Issues a fresh
/// token (the prior raw token is unrecoverable). Returns `false` if throttled or
/// there is no pending token for `email`.
pub async fn resend_verification<S>(
    store: &S,
    email: &str,
    channel: &str,
    min_interval_secs: i64,
) -> Result<bool, AuthError>
where
    S: EmailVerificationTokenStore + NotificationJobStore,
{
    if !store.try_mark_resent(email, min_interval_secs).await? {
        return Ok(false);
    }
    store.invalidate_pending(email).await?;
    let raw = random_token_hex(32);
    store.issue(email, &sha256_hex(&raw), TOKEN_TTL_MINUTES, None).await?;
    store
        .enqueue(channel, email, VERIFICATION_TEMPLATE, serde_json::json!({ "token": raw }), None)
        .await?;
    Ok(true)
}

// ── Login challenge (Phase 5): Email/SMS/LINE OTP ──────────────────────────

const OTP_TTL_MINUTES: i64 = 5;
const OTP_MAX_ATTEMPTS: i32 = 5;
const OTP_DIGITS: u32 = 6;
const MFA_CODE_TEMPLATE: &str = "mfa-code";

pub struct LoginOtpStart {
    pub challenge_id: Uuid,
    /// Dev/test only — the raw OTP. Production delivers it via notification.
    pub dev_code: Option<String>,
}

/// Issue an Email/SMS/LINE OTP login challenge: generate a numeric code, store
/// its hash (never the code), and enqueue a notification carrying the code.
/// TOTP-based MFA does not use this path (it verifies against `user_mfa`).
pub async fn issue_login_otp<S>(
    store: &S,
    user_id: Uuid,
    kind: &str,
    destination: &str,
    channel: &str,
) -> Result<LoginOtpStart, AuthError>
where
    S: LoginChallengeStore + NotificationJobStore,
{
    let code = random_numeric_code(OTP_DIGITS);
    let id = store
        .issue(user_id, kind, &sha256_hex(&code), destination, OTP_TTL_MINUTES, OTP_MAX_ATTEMPTS)
        .await?;
    let corr = format!("login-otp:{}", id);
    store
        .enqueue(channel, destination, MFA_CODE_TEMPLATE, serde_json::json!({ "code": code }), Some(&corr))
        .await?;
    Ok(LoginOtpStart { challenge_id: id, dev_code: Some(code) })
}

/// Verify a submitted OTP for the user's active login challenge. The caller maps
/// any failure to a generic client response (do not leak which variant).
pub async fn verify_login_otp<S>(
    store: &S,
    user_id: Uuid,
    raw_code: &str,
) -> Result<ChallengeVerifyOutcome, AuthError>
where
    S: LoginChallengeStore,
{
    store.verify(user_id, &sha256_hex(raw_code)).await
}

// ── MFA setup (Phase 4): TOTP, reusing existing totp + MfaStore ────────────

use crate::store::{MfaStore, RecoveryCodeStore};

const MFA_FLOW_TYPE: &str = "mfa_setup";
const RECOVERY_CODE_COUNT: usize = 10;

pub struct MfaSetupStart {
    pub flow_id: Uuid,
    /// Base32 TOTP secret for the provisioning URI (shown once).
    pub secret: String,
}

/// Start TOTP MFA setup: generate a secret, store it INACTIVE (pending
/// confirmation), and track the flow. The secret is activated only after a
/// valid code is confirmed (see [`confirm_mfa_setup`]).
pub async fn start_mfa_setup<S>(store: &S, user_id: Uuid) -> Result<MfaSetupStart, AuthError>
where
    S: FlowPersistence + MfaStore,
{
    let flow_id = Uuid::new_v4();
    let now = Utc::now();
    store
        .create(FlowRecord {
            id: flow_id,
            session_id: format!("mfa-setup:{}", user_id),
            flow_type: MFA_FLOW_TYPE.into(),
            current_state: "SecretIssued".into(),
            guard_failure_count: 0,
            version: 0,
            created_at: now,
            updated_at: now,
            expires_at: now + Duration::minutes(10),
            completed_at: None,
            exit_state: None,
            summary: None,
        })
        .await?;
    let secret = crate::totp::generate_secret();
    store.upsert_pending(user_id, "totp", &secret).await?;
    store
        .record_transition(flow_id, Some("SetupStarted"), "SecretIssued", "MfaIssueSecret", None)
        .await?;
    Ok(MfaSetupStart { flow_id, secret })
}

pub struct MfaSetupConfirmed {
    /// Raw recovery codes — shown ONCE; only their hashes are stored.
    pub recovery_codes: Vec<String>,
}

/// Confirm TOTP setup with a code. On success, activates the secret, issues
/// recovery codes (hashed), and completes the flow. Wrong code → `PolicyDenied`.
/// Matches the existing handler's secret encoding (verifies over the base32
/// string bytes) for consistency.
pub async fn confirm_mfa_setup<S>(
    store: &S,
    user_id: Uuid,
    flow_id: Uuid,
    code: &str,
) -> Result<MfaSetupConfirmed, AuthError>
where
    S: FlowPersistence + MfaStore + RecoveryCodeStore,
{
    let mfa = store
        .find_any(user_id, "totp")
        .await?
        .ok_or_else(|| AuthError::NotFound("no pending TOTP secret".into()))?;
    if mfa.is_active {
        return Err(AuthError::Conflict("MFA already enabled".into()));
    }
    if !crate::totp::verify_totp(mfa.secret.as_bytes(), code, 30) {
        return Err(AuthError::PolicyDenied("invalid TOTP code".into()));
    }

    store.activate(user_id, "totp").await?;

    // Issue recovery codes: raw shown once, only hashes stored.
    let raw: Vec<String> = (0..RECOVERY_CODE_COUNT)
        .map(|_| crate::crypto::random_token_hex(4))
        .collect();
    let hashes: Vec<String> = raw.iter().map(|c| sha256_hex(c)).collect();
    store.replace_all(user_id, &hashes).await?;

    let flow = FlowPersistence::find(store, flow_id).await?;
    if let Some(f) = flow {
        store.update_state(flow_id, "RecoveryCodesIssued", f.version + 1).await?;
        store
            .record_transition(flow_id, Some("ConfirmationPending"), "Enabled", "MfaConfirmCodeGuard", None)
            .await?;
        store
            .complete(flow_id, "RecoveryCodesIssued", Some(serde_json::json!({ "user_id": user_id })))
            .await?;
    }

    Ok(MfaSetupConfirmed { recovery_codes: raw })
}
