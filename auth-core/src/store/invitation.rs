use crate::error::AuthError;
use crate::record::InvitationRecord;
use async_trait::async_trait;
use uuid::Uuid;

/// Invitation data access trait.
#[async_trait]
pub trait InvitationStore: Send + Sync {
    async fn create(&self, record: InvitationRecord) -> Result<(), AuthError>;
    async fn find_by_code(&self, code: &str) -> Result<Option<InvitationRecord>, AuthError>;
    async fn accept(&self, code: &str, user_id: Uuid) -> Result<(), AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<InvitationRecord>, AuthError>;
    /// テナント `tenant_id` に属する招待 `id` を取り消す。
    ///
    /// 招待 id だけで絞ると別テナントの招待も取り消せてしまうので、必ず
    /// テナントと組で絞る。取り消した行があれば `true`。
    async fn cancel(&self, tenant_id: Uuid, id: Uuid) -> Result<bool, AuthError>;
}
