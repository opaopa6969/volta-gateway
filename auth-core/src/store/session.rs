//! Session store trait + in-memory implementation.
//! Mirrors Java SessionStore interface.

use async_trait::async_trait;
use crate::error::AuthError;
use crate::record::SessionRecord;
use std::collections::HashMap;
use std::sync::Mutex;

/// Session store trait (1:1 from Java SessionStore).
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(&self, record: SessionRecord) -> Result<(), AuthError>;
    async fn find(&self, session_id: &str) -> Result<Option<SessionRecord>, AuthError>;
    async fn touch(&self, session_id: &str, new_expires_at: u64) -> Result<(), AuthError>;
    async fn mark_mfa_verified(&self, session_id: &str) -> Result<(), AuthError>;
    async fn revoke(&self, session_id: &str) -> Result<(), AuthError>;
    async fn revoke_all_for_user(&self, user_id: &str) -> Result<usize, AuthError>;
    async fn list_by_user(&self, user_id: &str) -> Result<Vec<SessionRecord>, AuthError>;
    async fn count_active(&self, user_id: &str) -> Result<usize, AuthError>;
    async fn cleanup_expired(&self) -> Result<usize, AuthError>;
}

/// In-memory session store (for testing and single-instance deployments).
pub struct InMemorySessionStore {
    sessions: Mutex<HashMap<String, SessionRecord>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self { Self::new() }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create(&self, record: SessionRecord) -> Result<(), AuthError> {
        let mut map = self.sessions.lock().unwrap();
        map.insert(record.session_id.clone(), record);
        Ok(())
    }

    async fn find(&self, session_id: &str) -> Result<Option<SessionRecord>, AuthError> {
        let map = self.sessions.lock().unwrap();
        Ok(map.get(session_id).filter(|r| r.is_valid_at(now_epoch())).cloned())
    }

    async fn touch(&self, session_id: &str, new_expires_at: u64) -> Result<(), AuthError> {
        let mut map = self.sessions.lock().unwrap();
        if let Some(rec) = map.get_mut(session_id) {
            rec.last_active_at = now_epoch();
            rec.expires_at = new_expires_at;
        }
        Ok(())
    }

    async fn mark_mfa_verified(&self, session_id: &str) -> Result<(), AuthError> {
        let mut map = self.sessions.lock().unwrap();
        if let Some(rec) = map.get_mut(session_id) {
            rec.mfa_verified_at = Some(now_epoch());
        }
        Ok(())
    }

    async fn revoke(&self, session_id: &str) -> Result<(), AuthError> {
        let mut map = self.sessions.lock().unwrap();
        if let Some(rec) = map.get_mut(session_id) {
            rec.invalidated_at = Some(now_epoch());
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &str) -> Result<usize, AuthError> {
        let mut map = self.sessions.lock().unwrap();
        let mut count = 0;
        let now = now_epoch();
        for rec in map.values_mut() {
            if rec.user_id == user_id && rec.invalidated_at.is_none() {
                rec.invalidated_at = Some(now);
                count += 1;
            }
        }
        Ok(count)
    }

    async fn list_by_user(&self, user_id: &str) -> Result<Vec<SessionRecord>, AuthError> {
        let map = self.sessions.lock().unwrap();
        Ok(map.values()
            .filter(|r| r.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn count_active(&self, user_id: &str) -> Result<usize, AuthError> {
        let map = self.sessions.lock().unwrap();
        let now = now_epoch();
        Ok(map.values()
            .filter(|r| r.user_id == user_id && r.is_valid_at(now))
            .count())
    }

    async fn cleanup_expired(&self) -> Result<usize, AuthError> {
        let mut map = self.sessions.lock().unwrap();
        let now = now_epoch();
        let before = map.len();
        map.retain(|_, r| r.is_valid_at(now));
        Ok(before - map.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session(id: &str, user: &str) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            user_id: user.into(),
            tenant_id: "tenant-1".into(),
            return_to: None,
            created_at: now_epoch(),
            last_active_at: now_epoch(),
            expires_at: now_epoch() + 3600,
            invalidated_at: None,
            mfa_verified_at: None,
            ip_address: Some("1.2.3.4".into()),
            user_agent: Some("test".into()),
            csrf_token: Some("csrf-abc".into()),
            email: Some("test@test.com".into()),
            tenant_slug: Some("acme".into()),
            roles: vec!["MEMBER".into()],
            display_name: Some("Test".into()),
        }
    }

    #[tokio::test]
    async fn create_and_find() {
        let store = InMemorySessionStore::new();
        store.create(test_session("s1", "u1")).await.unwrap();
        let found = store.find("s1").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, "u1");
    }

    #[tokio::test]
    async fn find_nonexistent() {
        let store = InMemorySessionStore::new();
        assert!(store.find("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_session() {
        let store = InMemorySessionStore::new();
        store.create(test_session("s1", "u1")).await.unwrap();
        store.revoke("s1").await.unwrap();
        assert!(store.find("s1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_all_for_user() {
        let store = InMemorySessionStore::new();
        store.create(test_session("s1", "u1")).await.unwrap();
        store.create(test_session("s2", "u1")).await.unwrap();
        store.create(test_session("s3", "u2")).await.unwrap();
        let count = store.revoke_all_for_user("u1").await.unwrap();
        assert_eq!(count, 2);
        assert!(store.find("s1").await.unwrap().is_none());
        assert!(store.find("s2").await.unwrap().is_none());
        assert!(store.find("s3").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn count_active() {
        let store = InMemorySessionStore::new();
        store.create(test_session("s1", "u1")).await.unwrap();
        store.create(test_session("s2", "u1")).await.unwrap();
        assert_eq!(store.count_active("u1").await.unwrap(), 2);
        store.revoke("s1").await.unwrap();
        assert_eq!(store.count_active("u1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn list_by_user() {
        let store = InMemorySessionStore::new();
        store.create(test_session("s1", "u1")).await.unwrap();
        store.create(test_session("s2", "u2")).await.unwrap();
        let list = store.list_by_user("u1").await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn mark_mfa_verified() {
        let store = InMemorySessionStore::new();
        store.create(test_session("s1", "u1")).await.unwrap();
        assert!(!store.find("s1").await.unwrap().unwrap().is_mfa_verified());
        store.mark_mfa_verified("s1").await.unwrap();
        assert!(store.find("s1").await.unwrap().unwrap().is_mfa_verified());
    }
}
