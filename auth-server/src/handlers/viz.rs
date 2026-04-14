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

/// GET /viz/flows — public static graph listing flow definitions by name.
///
/// The Java version embedded full Mermaid diagrams via `MermaidGenerator`.
/// The Rust auth-server currently exposes names + states only; the tramli
/// integration that produces the full graph data is pending (see
/// `docs/sync-from-java-2026-04-14.md` P2.2).
pub async fn list_flows() -> Response {
    Json(serde_json::json!({
        "flows": [
            {"name": "oidc", "states": ["INIT", "REDIRECTED", "CALLBACK_RECEIVED", "TOKEN_EXCHANGED", "USER_RESOLVED", "COMPLETE", "COMPLETE_MFA_PENDING", "TERMINAL_ERROR"]},
            {"name": "passkey", "states": ["INIT", "CHALLENGE_ISSUED", "ASSERTION_RECEIVED", "USER_RESOLVED", "COMPLETE", "TERMINAL_ERROR"]},
            {"name": "mfa", "states": ["CHALLENGE_SHOWN", "VERIFIED", "TERMINAL_ERROR", "EXPIRED"]},
            {"name": "invite", "states": ["CONSENT_SHOWN", "ACCOUNT_SWITCHING", "ACCEPTED", "COMPLETE", "TERMINAL_ERROR", "EXPIRED"]},
        ]
    })).into_response()
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
