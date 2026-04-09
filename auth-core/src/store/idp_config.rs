use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::{IdpConfigRecord, M2mClientRecord, PasskeyRecord};

#[async_trait]
pub trait IdpConfigStore: Send + Sync {
    async fn upsert(&self, config: IdpConfigRecord) -> Result<Uuid, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<IdpConfigRecord>, AuthError>;
    async fn find(&self, tenant_id: Uuid, provider_type: &str) -> Result<Option<IdpConfigRecord>, AuthError>;
}

#[async_trait]
pub trait M2mClientStore: Send + Sync {
    async fn create(&self, record: M2mClientRecord) -> Result<Uuid, AuthError>;
    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<M2mClientRecord>, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<M2mClientRecord>, AuthError>;
}

#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn create(&self, record: PasskeyRecord) -> Result<Uuid, AuthError>;
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, AuthError>;
    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<PasskeyRecord>, AuthError>;
    async fn update_counter(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError>;
    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<(), AuthError>;
    async fn count(&self, user_id: Uuid) -> Result<usize, AuthError>;
}
