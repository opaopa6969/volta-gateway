//! Health check + JWKS endpoints.

use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use tokio::time::timeout;

use crate::state::AppState;
use volta_auth_core::store::SigningKeyStore;

/// How long the database probe may take before /healthz gives up on it.
///
/// Without a cap, sqlx waits out the pool's acquire timeout (tens of seconds)
/// when the database is unreachable, and the health check inherits exactly the
/// hang it exists to report. The gateway polls this every 30s and the external
/// probe allows 10s, so the answer has to come back well inside both.
const DB_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// GET /healthz
///
/// Reports whether the server can reach its database, not merely that the
/// process is alive. This used to return `{"status":"ok"}` unconditionally —
/// it took `State(_state)` and never looked at it.
///
/// On 2026-09-14 the Postgres on :54329 was removed along with the retired
/// `volta-auth-proxy` compose stack that happened to host it. Every monitor
/// stayed green: this endpoint, the gateway's backend health check, and the
/// Cloudflare probe all answered 200, while `/login` hung for 20s on a
/// connection that never came. The only symptom that escaped was the gateway's
/// circuit breaker serving intermittent 503s — 14 of them against 398 timeouts
/// in six hours, i.e. an alert that fired late and looked flaky.
///
/// Auth can do nothing useful without its database, so "healthy" has to mean
/// "can reach it". A degraded answer is a 503 so the gateway takes the backend
/// out of rotation and fails fast, instead of holding every request open until
/// it times out.
pub async fn healthz(State(state): State<AppState>) -> Response {
    let probe = sqlx::query("SELECT 1").execute(state.db.pool());
    match timeout(DB_PROBE_TIMEOUT, probe).await {
        Ok(Ok(_)) => Json(serde_json::json!({"status": "ok", "database": "ok"})).into_response(),
        Ok(Err(e)) => {
            // The detail goes to the log, not the response: a connection error
            // carries the DSN, and /healthz is public.
            tracing::warn!(error = %e, "healthz: database probe failed");
            degraded("error")
        }
        Err(_) => {
            tracing::warn!(timeout_s = DB_PROBE_TIMEOUT.as_secs(), "healthz: database probe timed out");
            degraded("timeout")
        }
    }
}

fn degraded(database: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"status": "degraded", "database": database})),
    )
        .into_response()
}

/// GET /.well-known/jwks.json — JSON Web Key Set (Phase 3a).
///
/// Publishes the OP RS256 **public** keys so relying parties can verify
/// id/access tokens. Retired keys are kept (tokens they signed may still be in
/// flight); revoked keys are dropped. Legacy HS256 placeholder rows (not RSA
/// PEM) are silently skipped. The internal session JWT stays HS256 (shared
/// secret) and never appears here.
pub async fn jwks(State(state): State<AppState>) -> Response {
    let keys: Vec<serde_json::Value> = match SigningKeyStore::list(&state.db).await {
        Ok(rows) => rows
            .into_iter()
            .filter(|k| k.status != "revoked")
            .filter_map(|k| crate::op_keys::rsa_public_pem_to_jwk(&k.public_key, &k.kid))
            .collect(),
        Err(_) => Vec::new(),
    };
    Json(serde_json::json!({ "keys": keys })).into_response()
}
