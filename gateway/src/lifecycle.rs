//! Server-lifecycle decision logic, factored out of the hyper connection loop
//! in `main.rs` so it can be unit- and integration-tested without standing up
//! the full proxy.
//!
//! These are *pure* decisions — they take primitives (drain flag, health flag,
//! loopback flag) and return an outcome enum / status code. The actual HTTP
//! response construction and the side effects (flipping the shutdown atomic,
//! accepting sockets) stay in the caller; only the *judgement* lives here.
//!
//! Behaviour is identical to the previous inline implementation:
//! - `/healthz` returns 503 while draining, otherwise 200 if volta is healthy
//!   and 503 if it is degraded.
//! - `/admin/*` is loopback-only; non-loopback peers get 403.
//! - The accept loop stops taking new connections once the drain flag is set.

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};

/// Outcome of a `/healthz` evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// 200 — serving normally and the upstream auth service is reachable.
    Ok,
    /// 503 — auth service is unreachable (degraded) but we are still serving.
    Degraded,
    /// 503 — graceful drain in progress; the LB/CF should stop routing here.
    Draining,
}

impl HealthStatus {
    /// HTTP status code for this health state.
    pub fn status_code(self) -> u16 {
        match self {
            HealthStatus::Ok => 200,
            HealthStatus::Degraded | HealthStatus::Draining => 503,
        }
    }

    /// JSON body matching the historical `/healthz` payload.
    pub fn body(self) -> &'static str {
        match self {
            HealthStatus::Ok => r#"{"status":"ok","volta":"ok"}"#,
            HealthStatus::Degraded => r#"{"status":"degraded","volta":"down"}"#,
            HealthStatus::Draining => r#"{"status":"draining","volta":"unknown"}"#,
        }
    }
}

/// Decide the `/healthz` outcome.
///
/// `draining` short-circuits to [`HealthStatus::Draining`] regardless of the
/// upstream auth health (the auth probe is skipped entirely while draining, as
/// in the original inline logic). Otherwise the result reflects `volta_ok`.
pub fn healthz_status(draining: bool, volta_ok: bool) -> HealthStatus {
    if draining {
        HealthStatus::Draining
    } else if volta_ok {
        HealthStatus::Ok
    } else {
        HealthStatus::Degraded
    }
}

/// Whether the accept loop may take a *new* connection.
///
/// Once the drain flag is set we stop accepting and let in-flight connections
/// finish, so this is simply the negation of `draining`.
pub fn should_accept_new(draining: bool) -> bool {
    !draining
}

/// Whether an `/admin/*` request from a peer is allowed past the
/// localhost-only network gate. Non-loopback peers are rejected with 403; the
/// Bearer-token check (see [`crate::admin_auth`]) happens afterwards.
pub fn admin_loopback_allowed(peer_is_loopback: bool) -> bool {
    peer_is_loopback
}

// ── Response helpers (shared by main.rs and the integration tests) ───────────

type Body = BoxBody<Bytes, hyper::Error>;

fn json(status: u16, body: impl Into<Bytes>) -> hyper::Response<Body> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(body.into()).map_err(|e| match e {}).boxed())
        .unwrap()
}

/// Build the `/healthz` HTTP response for the given decision.
pub fn healthz_response(status: HealthStatus) -> hyper::Response<Body> {
    json(status.status_code(), status.body())
}

/// Build the 403 response returned to non-loopback `/admin/*` callers.
///
/// Mirrors the original inline response exactly: status 403 with the JSON body
/// but *no* `content-type` header.
pub fn admin_loopback_denied_response() -> hyper::Response<Body> {
    hyper::Response::builder()
        .status(403)
        .body(
            Full::new(Bytes::from(r#"{"error":"admin API is localhost only"}"#))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── healthz_status ───────────────────────────────────────────

    #[test]
    fn draining_overrides_health_to_503() {
        assert_eq!(healthz_status(true, true), HealthStatus::Draining);
        assert_eq!(healthz_status(true, false), HealthStatus::Draining);
        assert_eq!(HealthStatus::Draining.status_code(), 503);
    }

    #[test]
    fn healthy_when_not_draining_and_volta_ok() {
        assert_eq!(healthz_status(false, true), HealthStatus::Ok);
        assert_eq!(HealthStatus::Ok.status_code(), 200);
    }

    #[test]
    fn degraded_when_not_draining_and_volta_down() {
        assert_eq!(healthz_status(false, false), HealthStatus::Degraded);
        assert_eq!(HealthStatus::Degraded.status_code(), 503);
    }

    #[test]
    fn health_bodies_match_legacy_payloads() {
        assert_eq!(HealthStatus::Ok.body(), r#"{"status":"ok","volta":"ok"}"#);
        assert_eq!(
            HealthStatus::Degraded.body(),
            r#"{"status":"degraded","volta":"down"}"#
        );
        assert_eq!(
            HealthStatus::Draining.body(),
            r#"{"status":"draining","volta":"unknown"}"#
        );
    }

    // ── should_accept_new ────────────────────────────────────────

    #[test]
    fn accepts_until_draining() {
        assert!(should_accept_new(false));
        assert!(!should_accept_new(true));
    }

    // ── admin_loopback_allowed ───────────────────────────────────

    #[test]
    fn loopback_gate() {
        assert!(admin_loopback_allowed(true));
        assert!(!admin_loopback_allowed(false));
    }

    // ── response helpers ─────────────────────────────────────────

    #[test]
    fn healthz_response_status_codes() {
        assert_eq!(healthz_response(HealthStatus::Ok).status(), 200);
        assert_eq!(healthz_response(HealthStatus::Degraded).status(), 503);
        assert_eq!(healthz_response(HealthStatus::Draining).status(), 503);
    }

    #[test]
    fn loopback_denied_response_is_403() {
        assert_eq!(admin_loopback_denied_response().status(), 403);
    }
}
