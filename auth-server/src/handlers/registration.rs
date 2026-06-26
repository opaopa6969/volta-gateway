//! Passwordless registration endpoints (Phase 2). Thin HTTP layer over
//! `volta_auth_core::runtime`. Responses carry the flow state + next actions so
//! the client knows what to do next. No account-enumeration leaks: verify and
//! resend return generic responses regardless of whether the address exists.

use axum::{extract::State, response::IntoResponse, response::Response, Json};
use serde::Deserialize;

use volta_auth_core::runtime;

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct StartReq {
    pub email: String,
}

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
        .map_err(|_| ApiError::bad_request("INVALID_TOKEN", "invalid or expired verification token"))?;
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
