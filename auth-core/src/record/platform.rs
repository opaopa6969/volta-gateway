use chrono::{DateTime, Utc};
use uuid::Uuid;

// ─── Webhook ───────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct WebhookRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub endpoint_url: String,
    pub secret: String,
    pub events: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct OutboxRecord {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub attempt_count: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct WebhookDeliveryRecord {
    pub id: Uuid,
    pub outbox_event_id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub status: String,
    pub status_code: Option<i32>,
    pub response_body: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ─── Audit ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct AuditLogRecord {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub actor_id: Option<Uuid>,
    pub actor_ip: Option<String>,
    pub tenant_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub request_id: Uuid,
}

// ─── Device Trust ──────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct KnownDeviceRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub fingerprint: String,
    pub label: Option<String>,
    pub last_ip: Option<String>,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct TrustedDeviceRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub device_name: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

// ─── Billing ───────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct PlanRecord {
    pub id: String,
    pub name: String,
    pub max_members: i32,
    pub max_apps: i32,
    pub features: String,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct SubscriptionRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub plan_id: String,
    pub status: String,
    pub stripe_sub_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ─── Policy ────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[cfg_attr(feature = "postgres", derive(sqlx::FromRow))]
pub struct PolicyRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub resource: String,
    pub action: String,
    pub condition: serde_json::Value,
    pub effect: String,
    pub priority: i32,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}
