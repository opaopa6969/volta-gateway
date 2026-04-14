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
    let mut pubsub = client.get_async_connection().await?.into_pubsub();
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
}
