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

    pub static PASSKEY: FlowView = FlowView {
        name: "passkey",
        states: &[
            "INIT", "CHALLENGE_ISSUED", "ASSERTION_RECEIVED",
            "USER_RESOLVED", "COMPLETE", "TERMINAL_ERROR",
        ],
        initial: "INIT",
        terminals: &["COMPLETE", "TERMINAL_ERROR"],
        edges: &[
            Edge { from: "INIT", to: "CHALLENGE_ISSUED", label: "PasskeyChallengeProcessor" },
            Edge { from: "CHALLENGE_ISSUED", to: "ASSERTION_RECEIVED", label: "PasskeyAssertionGuard" },
            Edge { from: "ASSERTION_RECEIVED", to: "USER_RESOLVED", label: "PasskeyVerifyProcessor" },
            Edge { from: "USER_RESOLVED", to: "COMPLETE", label: "SessionIssueProcessor" },
            Edge { from: "CHALLENGE_ISSUED", to: "TERMINAL_ERROR", label: "guard_fail" },
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
