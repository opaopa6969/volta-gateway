use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::InvitationRecord;

/// Invitation data access trait.
#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create(&self, record: InvitationRecord) -> Result<(), AuthError>;
    async fn find_by_code(&self, code: &str) -> Result<Option<InvitationRecord>, AuthError>;
    async fn accept(&self, code: &str, user_id: Uuid) -> Result<(), AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<InvitationRecord>, AuthError>;
    async fn cancel(&self, id: Uuid) -> Result<(), AuthError>;
}
