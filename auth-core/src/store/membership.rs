use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::MembershipRecord;

/// Membership data access trait.
#[async_trait]
pub trait MembershipStore: Send + Sync {
    async fn find(&self, user_id: Uuid, tenant_id: Uuid) -> Result<Option<MembershipRecord>, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<MembershipRecord>, AuthError>;
    async fn create(&self, record: MembershipRecord) -> Result<(), AuthError>;
    async fn update_role(&self, id: Uuid, role: &str) -> Result<(), AuthError>;
    async fn deactivate(&self, id: Uuid) -> Result<(), AuthError>;
    async fn count_active_owners(&self, tenant_id: Uuid) -> Result<usize, AuthError>;
}
