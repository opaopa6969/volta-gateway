use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::TenantRecord;

/// Tenant data access trait.
#[async_trait]
pub trait TenantStore: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<TenantRecord>, AuthError>;
    async fn find_by_slug(&self, slug: &str) -> Result<Option<TenantRecord>, AuthError>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<TenantRecord>, AuthError>;
    async fn create(&self, record: TenantRecord) -> Result<TenantRecord, AuthError>;
    async fn create_personal(&self, user_id: Uuid, name: &str, slug: &str) -> Result<TenantRecord, AuthError>;
}
