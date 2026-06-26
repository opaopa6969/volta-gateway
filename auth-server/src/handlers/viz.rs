//! Visualization handlers (`/viz/*`, `/api/v1/admin/flows/*`) —
//! counterpart of Java `VizRouter` (`6315cc0` + `9b4fe2c`).
//!
//! Endpoints:
//!   - `GET /viz/auth/stream` — SSE stream of LOGIN_SUCCESS / LOGOUT / SESSION_EXPIRED (P1.2)
//!   - `GET /viz/flows` — static flow graph info (public)
//!   - `GET /api/v1/admin/flows/{flowId}/transitions` — per-flow replay (ADMIN)

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use futures_util::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::error::ApiError;
use crate::helpers::require_admin;
use crate::state::AppState;

/// GET /viz/auth/stream — SSE stream of LOGIN_SUCCESS / LOGOUT / SESSION_EXPIRED.
///
/// Requires ADMIN/OWNER scope since the stream exposes per-user auth activity
/// across the whole deployment.
pub async fn auth_stream(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let _ = require_admin(&state, &jar).await?;

    let rx = state.auth_events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|item| {
        item.ok().and_then(|ev| {
            serde_json::to_string(&ev).ok().map(|json| {
                Ok::<_, Infallible>(Event::default().event(ev.event_type.clone()).data(json))
            })
        })
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15))))
}

/// GET /viz/flows — flow graph listing with Mermaid source (backlog P1 #8).
pub async fn list_flows() -> Response {
    Json(serde_json::json!({ "flows": all_flows() })).into_response()
}

fn all_flows() -> Vec<serde_json::Value> {
    vec![
        build_flow_view(&flow_tables::OIDC),
        build_flow_view(&flow_tables::PASSKEY),
        build_flow_view(&flow_tables::MFA),
        build_flow_view(&flow_tables::INVITE),
        build_flow_view(&flow_tables::REGISTRATION),
        build_flow_view(&flow_tables::EMAIL_VERIFICATION),
        build_flow_view(&flow_tables::PASSWORD_RESET),
        build_flow_view(&flow_tables::MFA_SETUP),
        build_flow_view(&flow_tables::LOGIN_CHALLENGE),
    ]
}

struct FlowView {
    name: &'static str,
    states: &'static [&'static str],
    initial: &'static str,
    terminals: &'static [&'static str],
    edges: &'static [volta_auth_core::flow::mermaid::Edge],
}

fn build_flow_view(f: &FlowView) -> serde_json::Value {
    let mermaid = volta_auth_core::flow::mermaid::render(f.initial, f.terminals, f.edges);
    let transitions: Vec<serde_json::Value> = f
        .edges
        .iter()
        .map(|e| serde_json::json!({
            "from": e.from,
            "to": e.to,
            "label": e.label,
        }))
        .collect();
    serde_json::json!({
        "name": f.name,
        "states": f.states,
        "initial": f.initial,
        "terminals": f.terminals,
        "transitions": transitions,
        "mermaid": mermaid,
    })
}

/// Hand-maintained flow tables. A drift test (`tests::flow_tables_match_enum`)
/// is expected to live alongside each flow definition in auth-core once the
/// tramli enums are introspectable; until then, update here when states
/// change.
#[allow(non_snake_case, non_upper_case_globals)]
mod flow_tables {
    use super::FlowView;
    use volta_auth_core::flow::mermaid::Edge;

    pub static OIDC: FlowView = FlowView {
        name: "oidc",
        states: &[
            "INIT", "REDIRECTED", "CALLBACK_RECEIVED", "TOKEN_EXCHANGED",
            "USER_RESOLVED", "COMPLETE", "COMPLETE_MFA_PENDING", "TERMINAL_ERROR",
        ],
        initial: "INIT",
        terminals: &["COMPLETE", "COMPLETE_MFA_PENDING", "TERMINAL_ERROR"],
        edges: &[
            Edge { from: "INIT", to: "REDIRECTED", label: "OidcInitProcessor" },
            Edge { from: "REDIRECTED", to: "CALLBACK_RECEIVED", label: "OidcCallbackGuard" },
            Edge { from: "CALLBACK_RECEIVED", to: "TOKEN_EXCHANGED", label: "OidcTokenExchangeProcessor" },
            Edge { from: "TOKEN_EXCHANGED", to: "USER_RESOLVED", label: "UserResolveProcessor" },
            Edge { from: "USER_RESOLVED", to: "COMPLETE", label: "branch(no_mfa)" },
            Edge { from: "USER_RESOLVED", to: "COMPLETE_MFA_PENDING", label: "branch(mfa_required)" },
            Edge { from: "REDIRECTED", to: "TERMINAL_ERROR", label: "guard_fail" },
            Edge { from: "CALLBACK_RECEIVED", to: "TERMINAL_ERROR", label: "idp_error" },
        ],
    };

    // Reflects the real imperative runtime (handlers/passkey_flow.rs), not just
    // the happy-path assertion ceremony: BOTH registration (attestation) and
    // authentication (discoverable assertion), the sign-counter clone check,
    // and the error terminals actually hit in production (see passkey-ux-design.md).
    pub static PASSKEY: FlowView = FlowView {
        name: "passkey",
        states: &[
            "INIT",
            // registration (attestation) ceremony
            "REG_CHALLENGE", "ATTESTATION_RECEIVED", "REGISTERED",
            // authentication (discoverable assertion) ceremony
            "AUTH_CHALLENGE", "ASSERTION_RECEIVED", "USER_RESOLVED", "COUNTER_CHECKED", "COMPLETE",
            // terminals
            "TERMINAL_ERROR", "CLONE_REJECTED",
        ],
        initial: "INIT",
        terminals: &["REGISTERED", "COMPLETE", "TERMINAL_ERROR", "CLONE_REJECTED"],
        edges: &[
            // ── registration (register/start → create() → register/finish) ──
            Edge { from: "INIT", to: "REG_CHALLENGE", label: "register_start" },
            Edge { from: "REG_CHALLENGE", to: "ATTESTATION_RECEIVED", label: "attestation_ext" },
            Edge { from: "ATTESTATION_RECEIVED", to: "REGISTERED", label: "verify_and_store" },
            Edge { from: "REG_CHALLENGE", to: "TERMINAL_ERROR", label: "already_registered" },
            Edge { from: "ATTESTATION_RECEIVED", to: "TERMINAL_ERROR", label: "attestation_invalid" },
            // ── authentication (discover/start → get() → discover/finish) ──
            Edge { from: "INIT", to: "AUTH_CHALLENGE", label: "discover_start" },
            Edge { from: "AUTH_CHALLENGE", to: "ASSERTION_RECEIVED", label: "assertion_ext" },
            Edge { from: "ASSERTION_RECEIVED", to: "USER_RESOLVED", label: "verify_user_handle" },
            Edge { from: "USER_RESOLVED", to: "COUNTER_CHECKED", label: "sign_counter_check" },
            Edge { from: "COUNTER_CHECKED", to: "COMPLETE", label: "session_issue" },
            Edge { from: "COUNTER_CHECKED", to: "CLONE_REJECTED", label: "signcount_regression" },
            Edge { from: "AUTH_CHALLENGE", to: "TERMINAL_ERROR", label: "challenge_expired" },
            Edge { from: "ASSERTION_RECEIVED", to: "TERMINAL_ERROR", label: "invalid_signature" },
        ],
    };

    pub static MFA: FlowView = FlowView {
        name: "mfa",
        states: &["CHALLENGE_SHOWN", "VERIFIED", "TERMINAL_ERROR", "EXPIRED"],
        initial: "CHALLENGE_SHOWN",
        terminals: &["VERIFIED", "TERMINAL_ERROR", "EXPIRED"],
        edges: &[
            Edge { from: "CHALLENGE_SHOWN", to: "VERIFIED", label: "MfaCodeGuard" },
            Edge { from: "CHALLENGE_SHOWN", to: "TERMINAL_ERROR", label: "3x_incorrect" },
            Edge { from: "CHALLENGE_SHOWN", to: "EXPIRED", label: "ttl" },
        ],
    };

    pub static INVITE: FlowView = FlowView {
        name: "invite",
        states: &[
            "CONSENT_SHOWN", "ACCOUNT_SWITCHING", "ACCEPTED",
            "COMPLETE", "TERMINAL_ERROR", "EXPIRED",
        ],
        initial: "CONSENT_SHOWN",
        terminals: &["COMPLETE", "TERMINAL_ERROR", "EXPIRED"],
        edges: &[
            Edge { from: "CONSENT_SHOWN", to: "ACCEPTED", label: "EmailMatchGuard" },
            Edge { from: "CONSENT_SHOWN", to: "ACCOUNT_SWITCHING", label: "email_mismatch" },
            Edge { from: "ACCOUNT_SWITCHING", to: "ACCEPTED", label: "ResumeGuard" },
            Edge { from: "ACCEPTED", to: "COMPLETE", label: "InviteCompleteProcessor" },
            Edge { from: "CONSENT_SHOWN", to: "TERMINAL_ERROR", label: "invite_expired" },
            Edge { from: "ACCOUNT_SWITCHING", to: "EXPIRED", label: "resume_timeout" },
        ],
    };

    // External (HTTP-guarded) transitions per flow — input to rule #4 of
    // `auth-core::flow::validate`. We list only the primary "success" edge of
    // each guard; failure / branch edges ride on the same external input.
    pub static OIDC_EXTERNAL: [Edge; 1] = [
        Edge { from: "REDIRECTED", to: "CALLBACK_RECEIVED", label: "OidcCallbackGuard" },
    ];
    pub static PASSKEY_EXTERNAL: [Edge; 2] = [
        Edge { from: "REG_CHALLENGE", to: "ATTESTATION_RECEIVED", label: "attestation_ext" },
        Edge { from: "AUTH_CHALLENGE", to: "ASSERTION_RECEIVED", label: "assertion_ext" },
    ];
    pub static MFA_EXTERNAL: [Edge; 1] = [
        Edge { from: "CHALLENGE_SHOWN", to: "VERIFIED", label: "MfaCodeGuard" },
    ];
    pub static INVITE_EXTERNAL: [Edge; 2] = [
        Edge { from: "CONSENT_SHOWN", to: "ACCEPTED", label: "EmailMatchGuard" },
        Edge { from: "ACCOUNT_SWITCHING", to: "ACCEPTED", label: "ResumeGuard" },
    ];

    // ── Phase 2 flows (auth-core/src/flow/{registration,email_verification,
    //    password_reset,mfa_setup,login_challenge}.rs). Display names are
    //    SCREAMING_SNAKE; edges mirror the tramli definitions. ──
    pub static REGISTRATION: FlowView = FlowView {
        name: "registration",
        states: &[
            "START", "EMAIL_VERIFICATION_PENDING", "EMAIL_VERIFIED",
            "MFA_SETUP_OPTIONAL", "COMPLETED", "CANCELLED",
        ],
        initial: "START",
        terminals: &["COMPLETED", "CANCELLED"],
        edges: &[
            Edge { from: "START", to: "EMAIL_VERIFICATION_PENDING", label: "RegIssueVerification" },
            Edge { from: "EMAIL_VERIFICATION_PENDING", to: "EMAIL_VERIFIED", label: "RegVerifyEmailGuard" },
            Edge { from: "EMAIL_VERIFIED", to: "MFA_SETUP_OPTIONAL", label: "branch(setup)" },
            Edge { from: "EMAIL_VERIFIED", to: "COMPLETED", label: "branch(skip)" },
            Edge { from: "MFA_SETUP_OPTIONAL", to: "COMPLETED", label: "RegMfaDoneGuard" },
            Edge { from: "EMAIL_VERIFICATION_PENDING", to: "CANCELLED", label: "expire_or_cancel" },
        ],
    };
    pub static REGISTRATION_EXTERNAL: [Edge; 2] = [
        Edge { from: "EMAIL_VERIFICATION_PENDING", to: "EMAIL_VERIFIED", label: "RegVerifyEmailGuard" },
        Edge { from: "MFA_SETUP_OPTIONAL", to: "COMPLETED", label: "RegMfaDoneGuard" },
    ];

    pub static EMAIL_VERIFICATION: FlowView = FlowView {
        name: "email_verification",
        states: &["TOKEN_ISSUED", "SEND_REQUESTED", "SENT", "VERIFIED", "CANCELLED"],
        initial: "TOKEN_ISSUED",
        terminals: &["VERIFIED", "CANCELLED"],
        edges: &[
            Edge { from: "TOKEN_ISSUED", to: "SEND_REQUESTED", label: "EvRequestSend" },
            Edge { from: "SEND_REQUESTED", to: "SENT", label: "EvMarkSentGuard" },
            Edge { from: "SENT", to: "VERIFIED", label: "EvVerifyTokenGuard" },
            Edge { from: "SEND_REQUESTED", to: "CANCELLED", label: "send_failed" },
        ],
    };
    pub static EMAIL_VERIFICATION_EXTERNAL: [Edge; 2] = [
        Edge { from: "SEND_REQUESTED", to: "SENT", label: "EvMarkSentGuard" },
        Edge { from: "SENT", to: "VERIFIED", label: "EvVerifyTokenGuard" },
    ];

    pub static PASSWORD_RESET: FlowView = FlowView {
        name: "password_reset",
        states: &[
            "REQUESTED", "TOKEN_ISSUED", "SEND_REQUESTED", "SENT",
            "TOKEN_VERIFIED", "PASSWORD_CHANGED", "COMPLETED", "CANCELLED",
        ],
        initial: "REQUESTED",
        terminals: &["COMPLETED", "CANCELLED"],
        edges: &[
            Edge { from: "REQUESTED", to: "TOKEN_ISSUED", label: "PrIssueResetToken" },
            Edge { from: "TOKEN_ISSUED", to: "SEND_REQUESTED", label: "PrRequestSend" },
            Edge { from: "SEND_REQUESTED", to: "SENT", label: "PrMarkSentGuard" },
            Edge { from: "SENT", to: "TOKEN_VERIFIED", label: "PrVerifyResetTokenGuard" },
            Edge { from: "TOKEN_VERIFIED", to: "PASSWORD_CHANGED", label: "PrChangePasswordGuard" },
            Edge { from: "PASSWORD_CHANGED", to: "COMPLETED", label: "PrComplete" },
            Edge { from: "SEND_REQUESTED", to: "CANCELLED", label: "expire" },
        ],
    };
    pub static PASSWORD_RESET_EXTERNAL: [Edge; 3] = [
        Edge { from: "SEND_REQUESTED", to: "SENT", label: "PrMarkSentGuard" },
        Edge { from: "SENT", to: "TOKEN_VERIFIED", label: "PrVerifyResetTokenGuard" },
        Edge { from: "TOKEN_VERIFIED", to: "PASSWORD_CHANGED", label: "PrChangePasswordGuard" },
    ];

    pub static MFA_SETUP: FlowView = FlowView {
        name: "mfa_setup",
        states: &[
            "NOT_CONFIGURED", "SETUP_STARTED", "SECRET_ISSUED",
            "CONFIRMATION_PENDING", "ENABLED", "RECOVERY_CODES_ISSUED", "CANCELLED",
        ],
        initial: "NOT_CONFIGURED",
        terminals: &["RECOVERY_CODES_ISSUED", "CANCELLED"],
        edges: &[
            Edge { from: "NOT_CONFIGURED", to: "SETUP_STARTED", label: "MfaStartSetupGuard" },
            Edge { from: "SETUP_STARTED", to: "SECRET_ISSUED", label: "MfaIssueSecret" },
            Edge { from: "SECRET_ISSUED", to: "CONFIRMATION_PENDING", label: "MfaPresentSecret" },
            Edge { from: "CONFIRMATION_PENDING", to: "ENABLED", label: "MfaConfirmCodeGuard" },
            Edge { from: "ENABLED", to: "RECOVERY_CODES_ISSUED", label: "MfaIssueRecoveryCodes" },
            Edge { from: "CONFIRMATION_PENDING", to: "CANCELLED", label: "cancel" },
        ],
    };
    pub static MFA_SETUP_EXTERNAL: [Edge; 2] = [
        Edge { from: "NOT_CONFIGURED", to: "SETUP_STARTED", label: "MfaStartSetupGuard" },
        Edge { from: "CONFIRMATION_PENDING", to: "ENABLED", label: "MfaConfirmCodeGuard" },
    ];

    pub static LOGIN_CHALLENGE: FlowView = FlowView {
        name: "login_challenge",
        states: &[
            "PASSWORD_ACCEPTED", "MFA_REQUIRED", "CHALLENGE_SENT",
            "CHALLENGE_VERIFIED", "LOGIN_GRANTED", "LOGIN_DENIED",
        ],
        initial: "PASSWORD_ACCEPTED",
        terminals: &["LOGIN_GRANTED", "LOGIN_DENIED"],
        edges: &[
            Edge { from: "PASSWORD_ACCEPTED", to: "MFA_REQUIRED", label: "branch(mfa)" },
            Edge { from: "PASSWORD_ACCEPTED", to: "LOGIN_GRANTED", label: "branch(grant)" },
            Edge { from: "MFA_REQUIRED", to: "CHALLENGE_SENT", label: "LcSendChallenge" },
            Edge { from: "CHALLENGE_SENT", to: "CHALLENGE_VERIFIED", label: "LcVerifyChallengeGuard" },
            Edge { from: "CHALLENGE_VERIFIED", to: "LOGIN_GRANTED", label: "LcGrant" },
            Edge { from: "CHALLENGE_SENT", to: "LOGIN_DENIED", label: "deny" },
        ],
    };
    pub static LOGIN_CHALLENGE_EXTERNAL: [Edge; 1] = [
        Edge { from: "CHALLENGE_SENT", to: "CHALLENGE_VERIFIED", label: "LcVerifyChallengeGuard" },
    ];
}

/// Expose the same descriptors to `auth-core::flow::validate` at startup
/// (backlog P2 #9). Returns one descriptor per flow so `main.rs` can iterate.
pub fn flow_descriptors() -> [volta_auth_core::flow::validate::FlowDescriptor; 9] {
    use volta_auth_core::flow::validate::FlowDescriptor;
    [
        FlowDescriptor {
            name: flow_tables::OIDC.name,
            states: flow_tables::OIDC.states,
            initial: flow_tables::OIDC.initial,
            terminals: flow_tables::OIDC.terminals,
            edges: flow_tables::OIDC.edges,
            // OIDC has one external guard (REDIRECTED → CALLBACK_RECEIVED).
            external_edges: &flow_tables::OIDC_EXTERNAL,
            // Rules #6 and #7: processors and aliases populated when tramli
            // exposes requires/produces and @FlowData aliases (see issue #60).
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::PASSKEY.name,
            states: flow_tables::PASSKEY.states,
            initial: flow_tables::PASSKEY.initial,
            terminals: flow_tables::PASSKEY.terminals,
            edges: flow_tables::PASSKEY.edges,
            external_edges: &flow_tables::PASSKEY_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::MFA.name,
            states: flow_tables::MFA.states,
            initial: flow_tables::MFA.initial,
            terminals: flow_tables::MFA.terminals,
            edges: flow_tables::MFA.edges,
            external_edges: &flow_tables::MFA_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::INVITE.name,
            states: flow_tables::INVITE.states,
            initial: flow_tables::INVITE.initial,
            terminals: flow_tables::INVITE.terminals,
            edges: flow_tables::INVITE.edges,
            external_edges: &flow_tables::INVITE_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::REGISTRATION.name,
            states: flow_tables::REGISTRATION.states,
            initial: flow_tables::REGISTRATION.initial,
            terminals: flow_tables::REGISTRATION.terminals,
            edges: flow_tables::REGISTRATION.edges,
            external_edges: &flow_tables::REGISTRATION_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::EMAIL_VERIFICATION.name,
            states: flow_tables::EMAIL_VERIFICATION.states,
            initial: flow_tables::EMAIL_VERIFICATION.initial,
            terminals: flow_tables::EMAIL_VERIFICATION.terminals,
            edges: flow_tables::EMAIL_VERIFICATION.edges,
            external_edges: &flow_tables::EMAIL_VERIFICATION_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::PASSWORD_RESET.name,
            states: flow_tables::PASSWORD_RESET.states,
            initial: flow_tables::PASSWORD_RESET.initial,
            terminals: flow_tables::PASSWORD_RESET.terminals,
            edges: flow_tables::PASSWORD_RESET.edges,
            external_edges: &flow_tables::PASSWORD_RESET_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::MFA_SETUP.name,
            states: flow_tables::MFA_SETUP.states,
            initial: flow_tables::MFA_SETUP.initial,
            terminals: flow_tables::MFA_SETUP.terminals,
            edges: flow_tables::MFA_SETUP.edges,
            external_edges: &flow_tables::MFA_SETUP_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
        FlowDescriptor {
            name: flow_tables::LOGIN_CHALLENGE.name,
            states: flow_tables::LOGIN_CHALLENGE.states,
            initial: flow_tables::LOGIN_CHALLENGE.initial,
            terminals: flow_tables::LOGIN_CHALLENGE.terminals,
            edges: flow_tables::LOGIN_CHALLENGE.edges,
            external_edges: &flow_tables::LOGIN_CHALLENGE_EXTERNAL,
            processors: &[],
            flow_data_aliases: &[],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_descriptors_pass_startup_validation() {
        // Mirrors the startup gate in main.rs: every flow descriptor (incl. the
        // 5 Phase-2 flows) must validate, else the process would exit(1).
        let descs = flow_descriptors();
        for desc in &descs {
            volta_auth_core::flow::validate::validate(desc)
                .unwrap_or_else(|e| panic!("flow '{}' failed validation: {:?}", desc.name, e));
        }
        let refs: Vec<&volta_auth_core::flow::validate::FlowDescriptor> = descs.iter().collect();
        assert!(
            volta_auth_core::flow::validate::validate_global_aliases(&refs).is_empty(),
            "cross-flow alias validation failed"
        );
    }

    #[test]
    fn every_flow_renders_mermaid() {
        for flow in all_flows() {
            let name = flow["name"].as_str().unwrap();
            let mermaid = flow["mermaid"].as_str().unwrap();
            assert!(!mermaid.is_empty(), "flow {} missing mermaid", name);
            assert!(mermaid.contains("stateDiagram-v2"), "flow {} bad header", name);
            assert!(mermaid.contains("[*] -->"), "flow {} no initial arrow", name);
        }
    }

    #[test]
    fn every_flow_has_initial_in_states() {
        let flows = [
            &flow_tables::OIDC, &flow_tables::PASSKEY,
            &flow_tables::MFA, &flow_tables::INVITE,
        ];
        for f in flows {
            assert!(
                f.states.contains(&f.initial),
                "flow {} initial state {} not in states list",
                f.name, f.initial
            );
        }
    }

    #[test]
    fn every_flow_terminals_are_states() {
        let flows = [
            &flow_tables::OIDC, &flow_tables::PASSKEY,
            &flow_tables::MFA, &flow_tables::INVITE,
        ];
        for f in flows {
            for t in f.terminals {
                assert!(
                    f.states.contains(t),
                    "flow {} terminal {} not in states list",
                    f.name, t
                );
            }
        }
    }

    #[test]
    fn every_edge_endpoint_is_declared_state() {
        let flows = [
            &flow_tables::OIDC, &flow_tables::PASSKEY,
            &flow_tables::MFA, &flow_tables::INVITE,
        ];
        for f in flows {
            for e in f.edges {
                assert!(f.states.contains(&e.from), "flow {} edge from {}", f.name, e.from);
                assert!(f.states.contains(&e.to), "flow {} edge to {}", f.name, e.to);
            }
        }
    }
}

/// GET /api/v1/admin/flows/{flow_id}/transitions — flow replay (ADMIN only).
///
/// Mirrors Java `VizRouter#listTransitions`. Returns every transition the flow
/// went through, ordered oldest-first. 404 when the flow does not exist;
/// transitions alone may legitimately be empty.
pub async fn flow_transitions(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(flow_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&state, &jar).await?;

    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM auth_flows WHERE id = $1"
    )
    .bind(flow_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    if exists.is_none() {
        return Err(ApiError::bad_request("NOT_FOUND", "flow not found"));
    }

    let rows: Vec<(i64, Option<String>, String, String, Option<serde_json::Value>, Option<String>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, from_state, to_state, trigger, context_snapshot, error_detail, created_at \
             FROM auth_flow_transitions WHERE flow_id = $1 ORDER BY created_at ASC"
        )
        .bind(flow_id)
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let transitions: Vec<_> = rows.into_iter().map(|(id, from, to, trigger, ctx, err, at)| {
        serde_json::json!({
            "id": id,
            "from_state": from,
            "to_state": to,
            "trigger": trigger,
            "context_snapshot": ctx,
            "error_detail": err,
            "created_at": at.to_rfc3339(),
        })
    }).collect();

    Ok(Json(serde_json::json!({
        "flow_id": flow_id,
        "transitions": transitions,
    })).into_response())
}
