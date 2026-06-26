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

use crate::crypto::{random_token_hex, sha256_hex};
use crate::error::AuthError;
use crate::record::FlowRecord;
use crate::store::{EmailVerificationTokenStore, FlowPersistence, NotificationJobStore};

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
