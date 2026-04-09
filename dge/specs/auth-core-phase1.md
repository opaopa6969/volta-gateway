# Spec: auth-core Phase 1 — Session Store, Policy Engine, Token Management

> Generated: 2026-04-09
> Source: DD-005, Java volta-auth-proxy (SessionStore.java, PolicyEngine.java, JwtService.java, AuthService.java)
> Depends on: Phase 0 (JWT verify) ✅ Done

## 1. Overview

Phase 1 は auth-core に「セッション管理」と「ポリシーエンジン」を追加する。
Phase 0 の JWT verify は stateless (cookie のみ)。Phase 1 で stateful なセッション管理を導入。

### やること
- SessionStore trait + InMemorySessionStore
- SessionRecord (user_id, tenant_id, roles, created_at, expires_at, device_info)
- PolicyEngine (role check, tenant isolation, IP restriction, rate limit per user)
- Token refresh + rotation
- Session revocation (logout, admin force-logout)

### やらないこと (Phase 2+)
- OIDC flow (Phase 2)
- MFA flow (Phase 2.5)
- DB persistence (SqlSessionStore は Phase 2 で FlowStore trait と統合)

## 2. Data Model

### SessionRecord

```rust
pub struct SessionRecord {
    pub session_id: String,
    pub user_id: String,
    pub email: Option<String>,
    pub tenant_id: Option<String>,
    pub tenant_slug: Option<String>,
    pub roles: Vec<String>,
    pub app_id: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub client_ip: Option<String>,
    pub created_at: u64,       // Unix timestamp
    pub expires_at: u64,       // Unix timestamp
    pub last_accessed: u64,    // Unix timestamp (sliding window)
    pub refresh_token: Option<String>,
    pub revoked: bool,
}
```

### PolicyRule

```rust
pub enum PolicyRule {
    RequireRole(String),                    // "ADMIN", "MEMBER"
    RequireTenant(String),                  // tenant_id must match
    DenyIp(Vec<ipnet::IpNet>),             // block CIDRs
    AllowIp(Vec<ipnet::IpNet>),            // allow only CIDRs
    MaxSessionsPerUser(usize),             // e.g. 5
    MaxSessionsPerDevice(usize),           // e.g. 1
    RequireRecentAuth(Duration),           // MFA step-up if session > N minutes
}
```

## 3. Traits

### SessionStore

```rust
pub trait SessionStore: Send + Sync {
    fn create(&self, record: SessionRecord) -> Result<(), AuthError>;
    fn get(&self, session_id: &str) -> Result<Option<SessionRecord>, AuthError>;
    fn update_last_accessed(&self, session_id: &str) -> Result<(), AuthError>;
    fn revoke(&self, session_id: &str) -> Result<(), AuthError>;
    fn revoke_all_for_user(&self, user_id: &str) -> Result<usize, AuthError>;
    fn list_by_user(&self, user_id: &str) -> Result<Vec<SessionRecord>, AuthError>;
    fn cleanup_expired(&self) -> Result<usize, AuthError>;
}
```

### PolicyEngine

```rust
pub struct PolicyEngine {
    global_rules: Vec<PolicyRule>,
    per_route_rules: HashMap<String, Vec<PolicyRule>>,  // host → rules
}

impl PolicyEngine {
    pub fn evaluate(
        &self,
        session: &SessionRecord,
        host: &str,
        client_ip: &std::net::IpAddr,
    ) -> PolicyResult;
}

pub enum PolicyResult {
    Allow,
    Deny(String),           // reason
    RequireMfa,             // step-up auth
    RequireReauth,          // session too old
}
```

## 4. Token Management

### Refresh Token Rotation

```
1. Client sends refresh_token
2. auth-core validates refresh_token against SessionStore
3. If valid: issue new JWT + new refresh_token, revoke old refresh_token
4. If revoked: revoke ALL sessions for user (token theft detection)
```

### Session Revocation

```
POST /auth/logout          → revoke current session
POST /auth/logout-all      → revoke all sessions for user
POST /admin/revoke-user    → admin force-revoke (via admin API)
```

## 5. Integration with Gateway

```rust
// gateway auth.rs — enhanced check flow
pub async fn check(&self, ...) -> AuthResult {
    // 1. In-process JWT verify (Phase 0) ✅
    // 2. NEW: Check session not revoked (Phase 1)
    // 3. NEW: Policy engine evaluation (Phase 1)
    // 4. Fallback: HTTP volta-auth-proxy
}
```

## 6. File Structure

```
auth-core/src/
  lib.rs          ✅ exists
  jwt.rs          ✅ Phase 0 done
  session.rs      ✅ Phase 0 done (cookie extraction)
  store.rs        📋 Phase 1 — SessionStore trait + InMemorySessionStore
  record.rs       📋 Phase 1 — SessionRecord
  policy.rs       📋 Phase 1 — PolicyEngine + PolicyRule
  token.rs        📋 Phase 1 — Token refresh, rotation, revocation
  error.rs        📋 Phase 1 — AuthError enum
```

## 7. Tests

```
auth-core tests (target: +15 tests):
  - InMemorySessionStore CRUD (create, get, revoke, list, cleanup)
  - PolicyEngine (role check, tenant isolation, IP deny/allow, max sessions)
  - Token refresh rotation (valid, expired, revoked → revoke-all)
  - Session revocation (single, all-for-user)
  - Integration: JWT verify + session check + policy
```

## 8. Done の定義

- [ ] SessionStore trait + InMemorySessionStore (5 tests)
- [ ] SessionRecord with all fields
- [ ] PolicyEngine with 5+ rules (5 tests)
- [ ] Token refresh rotation (3 tests)
- [ ] Session revocation (2 tests)
- [ ] Gateway integration (auth.rs enhanced check)
- [ ] Total: 90 + 15 = 105 tests pass
