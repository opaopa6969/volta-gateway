//! Auth event bus — SSE fan-out for `/viz/auth/stream` (P1.2 + P1 #7).
//!
//! Two layers:
//!
//! - **Local**: `tokio::sync::broadcast` — every SSE client on this
//!   process subscribes here.
//! - **Cross-instance (optional)**: Redis pub/sub bridge, enabled when
//!   `REDIS_URL` is set. See `arch/redis-sse-bridge.md` for rationale.
//!
//! Events are published by handlers after successful logins / logouts and
//! arrive at SSE subscribers via the local broadcast regardless of origin.

use std::time::SystemTime;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use volta_auth_core::record::AuditLogRecord;
use volta_auth_core::store::{AuditStore, OutboxStore};

/// Channel capacity — SSE clients that lag beyond this miss messages.
const CAPACITY: usize = 256;
/// Default Redis channel name; overridden by `REDIS_CHANNEL` env.
pub const DEFAULT_CHANNEL: &str = "volta:auth:events";

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
    /// Short random id identifying the emitting process (`_origin`). Used by
    /// the Redis bridge to ignore our own echoes. `None` on freshly-created
    /// events; filled in by `AuthEventBus::publish`.
    #[serde(default, rename = "_origin", skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
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
            origin: None,
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
    /// Unique id for this process, stamped onto every published event so the
    /// Redis subscriber can drop our own echoes.
    origin: String,
    /// Optional cross-instance bridge. `None` when `REDIS_URL` was unset at
    /// startup or the Redis connection failed.
    redis: Option<RedisPublisher>,
}

impl Default for AuthEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthEventBus {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CAPACITY);
        Self { tx, origin: random_origin(), redis: None }
    }

    /// Returns `true` if this bus will PUBLISH events into Redis.
    pub fn has_redis_bridge(&self) -> bool { self.redis.is_some() }

    pub fn origin(&self) -> &str { &self.origin }

    /// Attach a Redis publisher. Called once from `main.rs` after the bridge
    /// connects successfully.
    pub fn with_redis(mut self, redis: RedisPublisher) -> Self {
        self.redis = Some(redis);
        self
    }

    /// Local-only publish (used by the Redis subscriber to avoid a loop).
    pub fn publish_local(&self, ev: AuthEvent) {
        let _ = self.tx.send(ev);
    }

    /// Best-effort publish — stamps `origin` and replicates to Redis when a
    /// bridge is attached. Dropped if no subscribers anywhere.
    pub fn publish(&self, mut ev: AuthEvent) {
        if ev.origin.is_none() {
            ev.origin = Some(self.origin.clone());
        }
        if let Some(ref r) = self.redis {
            r.publish(ev.clone());
        }
        let _ = self.tx.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuthEvent> {
        self.tx.subscribe()
    }

    /// Publish + persist to `audit_logs` (backlog P2 #10). DB failure is
    /// **non-fatal** — the SSE side still fires and the HTTP caller is
    /// never stalled by an audit outage.
    pub async fn publish_and_audit<A>(
        &self,
        ev: AuthEvent,
        audit: &A,
        actor_ip: Option<String>,
        target_type: Option<String>,
        target_id: Option<String>,
        request_id: Option<Uuid>,
    ) where
        A: AuditStore + ?Sized,
    {
        let record = AuditLogRecord {
            id: 0, // DB fills via BIGSERIAL
            timestamp: chrono::Utc::now(),
            event_type: ev.event_type.clone(),
            actor_id: ev.user_id.as_deref().and_then(|s| Uuid::parse_str(s).ok()),
            actor_ip,
            tenant_id: ev.tenant_id.as_deref().and_then(|s| Uuid::parse_str(s).ok()),
            target_type,
            target_id,
            detail: ev.detail.clone(),
            request_id: request_id.unwrap_or_else(Uuid::new_v4),
        };
        if let Err(e) = audit.insert(record).await {
            tracing::warn!(event = %ev.event_type, error = %e, "audit_logs insert failed");
        }
        self.publish(ev);
    }

    /// Publish + persist to `audit_logs` + enqueue into `outbox_events` for
    /// external webhook delivery (issue #57).
    ///
    /// The outbox payload is **PII-minimized**: only `user_id`, `tenant_id`,
    /// `event_type`, and `timestamp` are included — no email, no IP address,
    /// no session detail. DB failures are **non-fatal** on both paths.
    ///
    /// Webhook subscribers can opt-in by adding an `auth.*` prefix pattern to
    /// the `events` column of their webhook row (e.g. `auth.login_success`).
    /// The event_type is normalized to lowercase with `auth.` prefix, so
    /// `LOGIN_SUCCESS` → `auth.login_success`.
    pub async fn publish_and_audit_outbox<A, O>(
        &self,
        ev: AuthEvent,
        audit: &A,
        outbox: &O,
        actor_ip: Option<String>,
        target_type: Option<String>,
        target_id: Option<String>,
        request_id: Option<Uuid>,
    ) where
        A: AuditStore + ?Sized,
        O: OutboxStore + ?Sized,
    {
        // Persist to audit_logs (same as publish_and_audit).
        let record = AuditLogRecord {
            id: 0,
            timestamp: chrono::Utc::now(),
            event_type: ev.event_type.clone(),
            actor_id: ev.user_id.as_deref().and_then(|s| Uuid::parse_str(s).ok()),
            actor_ip,
            tenant_id: ev.tenant_id.as_deref().and_then(|s| Uuid::parse_str(s).ok()),
            target_type,
            target_id,
            detail: ev.detail.clone(),
            request_id: request_id.unwrap_or_else(Uuid::new_v4),
        };
        if let Err(e) = audit.insert(record).await {
            tracing::warn!(event = %ev.event_type, error = %e, "audit_logs insert failed");
        }

        // Enqueue PII-minimized payload into outbox for webhook fan-out.
        let outbox_event_type = format!("auth.{}", ev.event_type.to_lowercase());
        let tenant_id_parsed = ev.tenant_id.as_deref().and_then(|s| Uuid::parse_str(s).ok());
        let payload = serde_json::json!({
            "event_type": outbox_event_type,
            "user_id": ev.user_id,
            "tenant_id": ev.tenant_id,
            "timestamp": ev.timestamp,
        });
        if let Err(e) = outbox.enqueue(tenant_id_parsed, &outbox_event_type, payload).await {
            tracing::warn!(event = %ev.event_type, error = %e, "outbox enqueue failed (non-fatal)");
        }

        self.publish(ev);
    }
}

fn random_origin() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Owned Redis client wrapper. PUBLISHes `serde_json::to_string(event)` onto
/// the configured channel. PUBLISH errors are logged but never surface to
/// callers — the local broadcast still succeeds.
#[derive(Clone)]
pub struct RedisPublisher {
    channel: String,
    tx: tokio::sync::mpsc::UnboundedSender<AuthEvent>,
}

impl RedisPublisher {
    pub fn channel(&self) -> &str { &self.channel }

    pub fn publish(&self, ev: AuthEvent) {
        let _ = self.tx.send(ev);
    }
}

/// Spawn the Redis pub/sub bridge.
///
/// Returns a `(RedisPublisher, JoinHandle)` on success. The caller should
/// store the publisher on `AuthEventBus::with_redis` and let the JoinHandle
/// live for the lifetime of the process.
///
/// Errors: connection failure at startup. Callers typically log & continue
/// without a bridge.
pub async fn spawn_redis_bridge(
    url: &str,
    channel: String,
    bus: AuthEventBus,
) -> Result<(RedisPublisher, tokio::task::JoinHandle<()>), redis::RedisError> {
    use redis::aio::ConnectionManager;
    use redis::AsyncCommands;

    let client = redis::Client::open(url)?;
    let publish_conn: ConnectionManager = ConnectionManager::new(client.clone()).await?;
    // Separate dedicated connection for subscribe (pub/sub needs exclusive conn).
    let mut pubsub = client.get_async_pubsub().await?;
    pubsub.subscribe(&channel).await?;

    // Subscriber task — pipes incoming messages back into the local broadcast.
    let bus_sub = bus.clone();
    let channel_for_task = channel.clone();
    let our_origin = bus.origin().to_string();
    let handle = tokio::spawn(async move {
        use tokio_stream::StreamExt;
        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            if let Ok(payload) = msg.get_payload::<String>() {
                if let Ok(ev) = serde_json::from_str::<AuthEvent>(&payload) {
                    if ev.origin.as_deref() == Some(&our_origin) {
                        continue; // our own echo — skip.
                    }
                    bus_sub.publish_local(ev);
                }
            }
        }
        tracing::warn!("redis auth-event subscriber stream ended (channel={})", channel_for_task);
    });

    // Publisher channel — decouples hot publish path from Redis IO latency.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<AuthEvent>();
    let mut pub_conn = publish_conn.clone();
    let channel_pub = channel.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let Ok(payload) = serde_json::to_string(&ev) {
                let _: Result<(), _> = pub_conn.publish(&channel_pub, payload).await;
            }
        }
    });

    Ok((RedisPublisher { channel, tx }, handle))
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

    #[tokio::test]
    async fn publish_stamps_origin_and_subscriber_sees_it() {
        let bus = AuthEventBus::new();
        let mut rx = bus.subscribe();
        bus.publish(AuthEvent::now("LOGIN_SUCCESS"));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.origin.as_deref(), Some(bus.origin()));
    }

    #[test]
    fn origin_ids_are_unique_per_bus() {
        let a = AuthEventBus::new();
        let b = AuthEventBus::new();
        assert_ne!(a.origin(), b.origin());
    }

    #[test]
    fn bus_without_redis_reports_false() {
        let bus = AuthEventBus::new();
        assert!(!bus.has_redis_bridge());
    }

    // ── publish_and_audit (P2 #10) ────────────────────────────

    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use volta_auth_core::error::AuthError;

    #[derive(Default)]
    struct MockAudit {
        inserts: Arc<Mutex<Vec<AuditLogRecord>>>,
        fail: bool,
    }
    #[async_trait]
    impl AuditStore for MockAudit {
        async fn insert(&self, r: AuditLogRecord) -> Result<(), AuthError> {
            if self.fail { return Err(AuthError::Internal("forced".into())); }
            self.inserts.lock().unwrap().push(r);
            Ok(())
        }
        async fn list(&self, _: uuid::Uuid, _: i64, _: i64) -> Result<Vec<AuditLogRecord>, AuthError> { Ok(vec![]) }
        async fn anonymize(&self, _: uuid::Uuid) -> Result<(), AuthError> { Ok(()) }
        async fn delete_flow_transitions_by_user(&self, _: uuid::Uuid) -> Result<(), AuthError> { Ok(()) }
    }

    #[tokio::test]
    async fn publish_and_audit_inserts_row() {
        let bus = AuthEventBus::new();
        let audit = MockAudit::default();
        let inserts = audit.inserts.clone();
        let uid = Uuid::new_v4();
        let ev = AuthEvent::now("LOGIN_SUCCESS")
            .with_user(uid.to_string())
            .with_session("sess-abc");
        bus.publish_and_audit(
            ev,
            &audit,
            Some("10.0.0.1".into()),
            Some("SESSION".into()),
            Some("sess-abc".into()),
            None,
        ).await;
        let rows = inserts.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "LOGIN_SUCCESS");
        assert_eq!(rows[0].actor_id, Some(uid));
        assert_eq!(rows[0].actor_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(rows[0].target_type.as_deref(), Some("SESSION"));
        assert_eq!(rows[0].target_id.as_deref(), Some("sess-abc"));
    }

    #[tokio::test]
    async fn publish_and_audit_db_failure_is_non_fatal() {
        // Even if AuditStore::insert errors, the broadcast still fires and the
        // caller returns normally — matches "best-effort" semantics.
        let bus = AuthEventBus::new();
        let mut rx = bus.subscribe();
        let audit = MockAudit { fail: true, ..Default::default() };
        bus.publish_and_audit(
            AuthEvent::now("LOGOUT").with_session("sess-xyz"),
            &audit,
            None, None, None, None,
        ).await;
        let got = rx.recv().await.unwrap();
        assert_eq!(got.event_type, "LOGOUT");
    }

    #[tokio::test]
    async fn publish_and_audit_preserves_detail() {
        let bus = AuthEventBus::new();
        let audit = MockAudit::default();
        let inserts = audit.inserts.clone();
        let mut ev = AuthEvent::now("TENANT_SWITCH");
        ev.detail = Some(serde_json::json!({"from": "t1", "to": "t2"}));
        bus.publish_and_audit(ev, &audit, None, None, None, None).await;
        let rows = inserts.lock().unwrap();
        assert_eq!(rows[0].detail.as_ref().unwrap()["to"], "t2");
    }

    // ── publish_and_audit_outbox (issue #57) ──────────────────

    #[derive(Debug, Default)]
    struct OutboxCall {
        tenant_id: Option<Uuid>,
        event_type: String,
        payload: serde_json::Value,
    }

    #[derive(Default)]
    struct MockOutbox {
        calls: Arc<Mutex<Vec<OutboxCall>>>,
        fail: bool,
    }

    use volta_auth_core::record::OutboxRecord;

    #[async_trait]
    impl OutboxStore for MockOutbox {
        async fn enqueue(
            &self,
            tenant_id: Option<Uuid>,
            event_type: &str,
            payload: serde_json::Value,
        ) -> Result<Uuid, AuthError> {
            if self.fail { return Err(AuthError::Internal("forced outbox".into())); }
            self.calls.lock().unwrap().push(OutboxCall {
                tenant_id,
                event_type: event_type.to_string(),
                payload,
            });
            Ok(Uuid::new_v4())
        }
        async fn claim_pending(&self, _: i64) -> Result<Vec<OutboxRecord>, AuthError> { Ok(vec![]) }
        async fn mark_published(&self, _: Uuid) -> Result<(), AuthError> { Ok(()) }
        async fn mark_retry(&self, _: Uuid, _: i32, _: &str) -> Result<(), AuthError> { Ok(()) }
        async fn delete_by_user(&self, _: Uuid) -> Result<(), AuthError> { Ok(()) }
    }

    #[tokio::test]
    async fn outbox_enqueue_called_with_minimized_payload() {
        let bus = AuthEventBus::new();
        let audit = MockAudit::default();
        let outbox = MockOutbox::default();
        let calls = outbox.calls.clone();

        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let ev = AuthEvent::now("LOGIN_SUCCESS")
            .with_user(uid.to_string())
            .with_tenant(tid.to_string())
            .with_session("sess-xyz");
        // Give the event a detail field that must NOT appear in outbox payload.
        let mut ev = ev;
        ev.detail = Some(serde_json::json!({"ip": "1.2.3.4", "email": "user@example.com"}));

        bus.publish_and_audit_outbox(ev, &audit, &outbox, None, None, None, None).await;

        let rows = calls.lock().unwrap();
        assert_eq!(rows.len(), 1, "exactly one outbox enqueue");
        assert_eq!(rows[0].event_type, "auth.login_success", "event_type normalized to auth.* prefix");
        assert_eq!(rows[0].tenant_id, Some(tid), "tenant_id forwarded");

        let p = &rows[0].payload;
        assert_eq!(p["event_type"], "auth.login_success");
        assert_eq!(p["user_id"].as_str(), Some(uid.to_string().as_str()));
        assert_eq!(p["tenant_id"].as_str(), Some(tid.to_string().as_str()));
        assert!(p.get("timestamp").is_some(), "timestamp present");
        // PII check: detail/email must NOT be in outbox payload.
        assert!(p.get("detail").is_none(), "detail must be stripped from outbox payload (PII)");
        assert!(p.get("session_id").is_none(), "session_id must not be in outbox payload");
    }

    #[tokio::test]
    async fn outbox_enqueue_uses_auth_dot_prefix_for_all_event_types() {
        let bus = AuthEventBus::new();
        let audit = MockAudit::default();
        let outbox = MockOutbox::default();
        let calls = outbox.calls.clone();

        bus.publish_and_audit_outbox(
            AuthEvent::now("LOGOUT"),
            &audit, &outbox,
            None, None, None, None,
        ).await;

        let rows = calls.lock().unwrap();
        assert_eq!(rows[0].event_type, "auth.logout");
    }

    #[tokio::test]
    async fn outbox_failure_is_non_fatal_sse_still_fires() {
        let bus = AuthEventBus::new();
        let mut rx = bus.subscribe();
        let audit = MockAudit::default();
        let outbox = MockOutbox { fail: true, ..Default::default() };

        bus.publish_and_audit_outbox(
            AuthEvent::now("LOGIN_SUCCESS"),
            &audit, &outbox,
            None, None, None, None,
        ).await;

        // SSE broadcast must still fire despite outbox failure.
        let got = rx.recv().await.unwrap();
        assert_eq!(got.event_type, "LOGIN_SUCCESS");
    }

    #[tokio::test]
    async fn outbox_audit_both_called() {
        // Both audit and outbox paths execute in a single call.
        let bus = AuthEventBus::new();
        let audit = MockAudit::default();
        let audit_rows = audit.inserts.clone();
        let outbox = MockOutbox::default();
        let outbox_calls = outbox.calls.clone();

        let uid = Uuid::new_v4();
        bus.publish_and_audit_outbox(
            AuthEvent::now("LOGIN_SUCCESS").with_user(uid.to_string()),
            &audit, &outbox,
            Some("10.0.0.1".into()),
            Some("SESSION".into()),
            Some("sess-1".into()),
            None,
        ).await;

        assert_eq!(audit_rows.lock().unwrap().len(), 1, "audit row inserted");
        assert_eq!(outbox_calls.lock().unwrap().len(), 1, "outbox enqueued");
    }
}
