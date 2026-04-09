use async_trait::async_trait;
use uuid::Uuid;
use crate::error::AuthError;
use crate::record::UserRecord;

/// User data access trait.
#[async_trait]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<UserRecord>, AuthError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, AuthError>;
    async fn find_by_google_sub(&self, google_sub: &str) -> Result<Option<UserRecord>, AuthError>;
    async fn upsert(&self, record: UserRecord) -> Result<UserRecord, AuthError>;
    async fn update_display_name(&self, id: Uuid, display_name: &str) -> Result<(), AuthError>;
    async fn soft_delete(&self, id: Uuid) -> Result<(), AuthError>;
}
