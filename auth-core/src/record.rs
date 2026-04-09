//! Session record — mirrors Java SessionRecord.

/// Session record (1:1 from Java volta-auth-proxy SessionRecord).
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub return_to: Option<String>,
    pub created_at: u64,
    pub last_active_at: u64,
    pub expires_at: u64,
    pub invalidated_at: Option<u64>,
    pub mfa_verified_at: Option<u64>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub csrf_token: Option<String>,
    // Extra fields for gateway headers
    pub email: Option<String>,
    pub tenant_slug: Option<String>,
    pub roles: Vec<String>,
    pub display_name: Option<String>,
}

impl SessionRecord {
    pub fn is_valid_at(&self, now_epoch: u64) -> bool {
        self.invalidated_at.is_none() && self.expires_at > now_epoch
    }

    pub fn is_mfa_verified(&self) -> bool {
        self.mfa_verified_at.is_some()
    }

    /// Convert to X-Volta-* headers.
    pub fn to_volta_headers(&self) -> std::collections::HashMap<String, String> {
        let mut h = std::collections::HashMap::new();
        h.insert("x-volta-user-id".into(), self.user_id.clone());
        if let Some(ref email) = self.email {
            h.insert("x-volta-email".into(), email.clone());
        }
        h.insert("x-volta-tenant-id".into(), self.tenant_id.clone());
        if let Some(ref slug) = self.tenant_slug {
            h.insert("x-volta-tenant-slug".into(), slug.clone());
        }
        if !self.roles.is_empty() {
            h.insert("x-volta-roles".into(), self.roles.join(","));
        }
        if let Some(ref name) = self.display_name {
            h.insert("x-volta-display-name".into(), name.clone());
        }
        h
    }
}
