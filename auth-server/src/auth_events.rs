//! Auth event bus — SSE fan-out for `/viz/auth/stream` (P1.2, Java `9b4fe2c`).
//!
//! In the Java implementation `AuditService` publishes `LOGIN_SUCCESS` /
//! `LOGOUT` / `SESSION_EXPIRED` events onto Redis channel `volta:auth:events`,
//! and `VizRouter` fans them out to SSE clients via a virtual subscriber
//! thread.
//!
//! The Rust port uses an in-process `tokio::sync::broadcast` channel as the
//! fan-out primitive. Events are published by handlers after successful
//! logins / logouts and consumed by SSE subscribers in `handlers::viz`.
//!
//! Multi-instance deployments need Redis pub/sub for cross-node fan-out; that
//! piece is deferred — the scaffolding here is single-instance-correct and
//! the hook for a Redis subscriber is called out below.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Channel capacity — SSE clients that lag beyond this miss messages.
const CAPACITY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub event_type: String,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub session_id: Option<String>,
    /// Epoch milliseconds.
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl AuthEvent {
    pub fn now(event_type: impl Into<String>) -> Self {
        let ts = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            event_type: event_type.into(),
            user_id: None,
            tenant_id: None,
            session_id: None,
            timestamp: ts,
            detail: None,
        }
    }

    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

#[derive(Clone)]
pub struct AuthEventBus {
    tx: broadcast::Sender<AuthEvent>,
}

impl Default for AuthEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthEventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CAPACITY);
        Self { tx }
    }

    /// Best-effort publish — silently drops the event when no subscribers are
    /// connected, matching the Java "fire and forget" semantics.
    pub fn publish(&self, ev: AuthEvent) {
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuthEvent> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publish_and_subscribe_roundtrip() {
        let bus = AuthEventBus::new();
        let mut rx = bus.subscribe();
        bus.publish(AuthEvent::now("LOGIN_SUCCESS").with_user("u-1"));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.event_type, "LOGIN_SUCCESS");
        assert_eq!(got.user_id.as_deref(), Some("u-1"));
    }

    #[tokio::test]
    async fn publish_with_no_subscribers_is_noop() {
        let bus = AuthEventBus::new();
        bus.publish(AuthEvent::now("LOGOUT"));
    }
}
