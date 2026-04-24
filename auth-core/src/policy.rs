//! Policy engine — role-based access control.
//! 1:1 from Java PolicyEngine.java.

use std::collections::{HashMap, HashSet};

/// Policy evaluation result.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyResult {
    Allow,
    Deny(String),
    RequireMfa,
    RequireReauth,
}

/// Role-based policy engine with hierarchy and permissions.
#[derive(Clone)]
pub struct PolicyEngine {
    hierarchy: Vec<String>,  // highest first: [OWNER, ADMIN, MEMBER, VIEWER]
    effective_permissions: HashMap<String, HashSet<String>>,
}

impl PolicyEngine {
    /// Create with default volta policy (OWNER > ADMIN > MEMBER > VIEWER).
    pub fn default_policy() -> Self {
        let hierarchy = vec!["OWNER".into(), "ADMIN".into(), "MEMBER".into(), "VIEWER".into()];
        let mut perms: HashMap<String, HashSet<String>> = HashMap::new();

        // VIEWER
        perms.insert("VIEWER".into(), ["read_only"].iter().map(|s| s.to_string()).collect());

        // MEMBER inherits VIEWER
        let mut member: HashSet<String> = perms["VIEWER"].clone();
        for p in &["use_apps", "view_own_profile", "update_own_profile", "manage_own_sessions",
                   "view_tenant_members", "switch_tenant", "accept_invitation"] {
            member.insert(p.to_string());
        }
        perms.insert("MEMBER".into(), member);

        // ADMIN inherits MEMBER
        let mut admin: HashSet<String> = perms["MEMBER"].clone();
        for p in &["invite_members", "remove_members", "change_member_role",
                   "view_invitations", "create_invitations", "cancel_invitations",
                   "change_tenant_name", "view_audit_logs"] {
            admin.insert(p.to_string());
        }
        perms.insert("ADMIN".into(), admin);

        // OWNER inherits ADMIN
        let mut owner: HashSet<String> = perms["ADMIN"].clone();
        for p in &["delete_tenant", "transfer_ownership", "manage_signing_keys", "change_tenant_slug"] {
            owner.insert(p.to_string());
        }
        perms.insert("OWNER".into(), owner);

        Self { hierarchy, effective_permissions: perms }
    }

    /// Check if a role has a permission (including inherited).
    pub fn can(&self, role: &str, permission: &str) -> bool {
        self.effective_permissions.get(role)
            .map(|perms| perms.contains(permission))
            .unwrap_or(false)
    }

    /// Check if any of the roles has the permission.
    pub fn can_any(&self, roles: &[String], permission: &str) -> bool {
        roles.iter().any(|r| self.can(r, permission))
    }

    /// Get rank of a role (0 = highest). Returns usize::MAX if unknown.
    pub fn rank(&self, role: &str) -> usize {
        self.hierarchy.iter().position(|r| r == role).unwrap_or(usize::MAX)
    }

    /// Check if role_a is at least as high as role_b.
    pub fn is_at_least(&self, role_a: &str, role_b: &str) -> bool {
        self.rank(role_a) <= self.rank(role_b)
    }

    /// Enforce that roles include at least min_role.
    pub fn enforce_min_role(&self, roles: &[String], min_role: &str) -> PolicyResult {
        if roles.iter().any(|r| self.is_at_least(r, min_role)) {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!("minimum role '{}' required", min_role))
        }
    }

    /// Enforce permission check.
    pub fn enforce_permission(&self, roles: &[String], permission: &str) -> PolicyResult {
        if self.can_any(roles, permission) {
            PolicyResult::Allow
        } else {
            PolicyResult::Deny(format!("permission '{}' denied", permission))
        }
    }

    /// Get hierarchy.
    pub fn hierarchy(&self) -> &[String] {
        &self.hierarchy
    }

    /// Get all permissions for a role.
    pub fn permissions(&self, role: &str) -> HashSet<String> {
        self.effective_permissions.get(role).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_hierarchy() {
        let policy = PolicyEngine::default_policy();
        assert_eq!(policy.hierarchy(), &["OWNER", "ADMIN", "MEMBER", "VIEWER"]);
    }

    #[test]
    fn owner_can_delete_tenant() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.can("OWNER", "delete_tenant"));
        assert!(!policy.can("ADMIN", "delete_tenant"));
    }

    #[test]
    fn admin_inherits_member() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.can("ADMIN", "use_apps")); // inherited from MEMBER
        assert!(policy.can("ADMIN", "invite_members")); // own permission
    }

    #[test]
    fn viewer_has_read_only() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.can("VIEWER", "read_only"));
        assert!(!policy.can("VIEWER", "use_apps"));
    }

    #[test]
    fn rank_ordering() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.rank("OWNER") < policy.rank("ADMIN"));
        assert!(policy.rank("ADMIN") < policy.rank("MEMBER"));
        assert!(policy.is_at_least("OWNER", "VIEWER"));
        assert!(!policy.is_at_least("VIEWER", "ADMIN"));
    }

    #[test]
    fn enforce_min_role() {
        let policy = PolicyEngine::default_policy();
        assert_eq!(
            policy.enforce_min_role(&["ADMIN".into()], "MEMBER"),
            PolicyResult::Allow
        );
        assert!(matches!(
            policy.enforce_min_role(&["VIEWER".into()], "ADMIN"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn enforce_permission() {
        let policy = PolicyEngine::default_policy();
        assert_eq!(
            policy.enforce_permission(&["MEMBER".into()], "use_apps"),
            PolicyResult::Allow
        );
        assert!(matches!(
            policy.enforce_permission(&["MEMBER".into()], "invite_members"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn can_any_multiple_roles() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.can_any(&["VIEWER".into(), "ADMIN".into()], "invite_members"));
    }

    // ── Additional boundary / edge-case tests ─────────────────

    #[test]
    fn unknown_role_has_no_permissions() {
        let policy = PolicyEngine::default_policy();
        assert!(!policy.can("SUPERUSER", "read_only"));
        assert!(!policy.can("", "read_only"));
    }

    #[test]
    fn can_any_with_empty_roles_is_false() {
        let policy = PolicyEngine::default_policy();
        assert!(!policy.can_any(&[], "read_only"));
    }

    #[test]
    fn unknown_role_has_max_rank() {
        let policy = PolicyEngine::default_policy();
        assert_eq!(policy.rank("NONEXISTENT"), usize::MAX);
    }

    #[test]
    fn is_at_least_same_role_is_true() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.is_at_least("ADMIN", "ADMIN"));
        assert!(policy.is_at_least("VIEWER", "VIEWER"));
    }

    #[test]
    fn owner_inherits_all_lower_permissions() {
        let policy = PolicyEngine::default_policy();
        // OWNER must have every permission that VIEWER has.
        for perm in policy.permissions("VIEWER") {
            assert!(
                policy.can("OWNER", &perm),
                "OWNER should inherit VIEWER permission '{}'", perm
            );
        }
        // OWNER must have every permission that MEMBER has.
        for perm in policy.permissions("MEMBER") {
            assert!(
                policy.can("OWNER", &perm),
                "OWNER should inherit MEMBER permission '{}'", perm
            );
        }
        // OWNER must have every permission that ADMIN has.
        for perm in policy.permissions("ADMIN") {
            assert!(
                policy.can("OWNER", &perm),
                "OWNER should inherit ADMIN permission '{}'", perm
            );
        }
    }

    #[test]
    fn enforce_min_role_with_multiple_roles_takes_highest() {
        let policy = PolicyEngine::default_policy();
        // User has both VIEWER and ADMIN — should satisfy ADMIN requirement.
        assert_eq!(
            policy.enforce_min_role(&["VIEWER".into(), "ADMIN".into()], "ADMIN"),
            PolicyResult::Allow
        );
    }

    #[test]
    fn permissions_unknown_role_returns_empty_set() {
        let policy = PolicyEngine::default_policy();
        assert!(policy.permissions("NONEXISTENT").is_empty());
    }

    #[test]
    fn viewer_cannot_manage_tenant() {
        let policy = PolicyEngine::default_policy();
        assert!(!policy.can("VIEWER", "delete_tenant"));
        assert!(!policy.can("VIEWER", "transfer_ownership"));
        assert!(!policy.can("VIEWER", "manage_signing_keys"));
    }

    #[test]
    fn member_cannot_invite_or_remove() {
        let policy = PolicyEngine::default_policy();
        assert!(!policy.can("MEMBER", "invite_members"));
        assert!(!policy.can("MEMBER", "remove_members"));
        assert!(!policy.can("MEMBER", "change_member_role"));
    }
}
