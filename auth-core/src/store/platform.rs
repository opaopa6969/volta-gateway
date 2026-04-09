use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::*;

// ─── Webhook ───────────────────────────────────────────────

#[async_trait]
pub trait WebhookStore: Send + Sync {
    async fn create(&self, record: WebhookRecord) -> Result<Uuid, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<WebhookRecord>, AuthError>;
    async fn find(&self, tenant_id: Uuid, id: Uuid) -> Result<Option<WebhookRecord>, AuthError>;
    async fn update(&self, id: Uuid, endpoint_url: &str, events: &str, is_active: bool) -> Result<(), AuthError>;
    async fn deactivate(&self, id: Uuid) -> Result<(), AuthError>;
}

#[async_trait]
pub trait OutboxStore: Send + Sync {
    async fn enqueue(&self, tenant_id: Option<Uuid>, event_type: &str, payload: serde_json::Value) -> Result<Uuid, AuthError>;
    async fn claim_pending(&self, limit: i64) -> Result<Vec<OutboxRecord>, AuthError>;
    async fn mark_published(&self, id: Uuid) -> Result<(), AuthError>;
    async fn mark_retry(&self, id: Uuid, attempt: i32, error: &str) -> Result<(), AuthError>;
}

#[async_trait]
pub trait WebhookDeliveryStore: Send + Sync {
    async fn insert(&self, record: WebhookDeliveryRecord) -> Result<(), AuthError>;
    async fn list_by_webhook(&self, webhook_id: Uuid, limit: i64) -> Result<Vec<WebhookDeliveryRecord>, AuthError>;
}

// ─── Audit ─────────────────────────────────────────────────

#[async_trait]
pub trait AuditStore: Send + Sync {
    async fn insert(&self, record: AuditLogRecord) -> Result<(), AuthError>;
    async fn list(&self, tenant_id: Uuid, offset: i64, limit: i64) -> Result<Vec<AuditLogRecord>, AuthError>;
    async fn anonymize(&self, user_id: Uuid) -> Result<(), AuthError>;
}

// ─── Device Trust ──────────────────────────────────────────

#[async_trait]
pub trait DeviceTrustStore: Send + Sync {
    async fn list_trusted(&self, user_id: Uuid) -> Result<Vec<TrustedDeviceRecord>, AuthError>;
    async fn create_trusted(&self, record: TrustedDeviceRecord) -> Result<(), AuthError>;
    async fn delete_trusted(&self, user_id: Uuid, device_id: Uuid) -> Result<(), AuthError>;
    async fn delete_all_trusted(&self, user_id: Uuid) -> Result<(), AuthError>;
}

// ─── Billing ───────────────────────────────────────────────

#[async_trait]
pub trait BillingStore: Send + Sync {
    async fn list_plans(&self) -> Result<Vec<PlanRecord>, AuthError>;
    async fn find_subscription(&self, tenant_id: Uuid) -> Result<Option<SubscriptionRecord>, AuthError>;
    async fn upsert_subscription(&self, record: SubscriptionRecord) -> Result<Uuid, AuthError>;
}

// ─── Policy ────────────────────────────────────────────────

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn create(&self, record: PolicyRecord) -> Result<Uuid, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<PolicyRecord>, AuthError>;
    async fn find_matching(&self, tenant_id: Uuid, resource: &str, action: &str) -> Result<Option<PolicyRecord>, AuthError>;
}
