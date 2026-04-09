# Session Handoff: volta-gateway + auth-core

> From: 2026-04-07〜09 セッション (3日間)
> To: 次回セッション

## 現状

### Workspace: 4 crates, 125 tests

```
volta-gateway/
  Cargo.toml              workspace root
  gateway/                HTTP reverse proxy (30+ features, 80 tests)
  auth-core/              Auth library (5 tramli SM flows, 45 tests)
  volta-bin/              Unified binary (gateway + auth in-process)
  tools/traefik-to-volta/ Config converter CLI
```

### Bench: 6.6x faster than Traefik

| Metric | Value |
|--------|-------|
| Proxy p50 | 0.252ms |
| vs Traefik p50 | **6.6x faster** |
| Auth in-process JWT | ~1µs (was 250µs HTTP) |
| SM full lifecycle | 4.86µs |

### tramli 3.6.1 + plugins

6 SM flows: proxy, token, OIDC, MFA, Passkey, Invite.
Plugins: lint, diagram, docs, testing, observability.

### Issues: 41 closed, 6 open (#37,39,43-47)

### DDs: 6 (CORS, L4, Accept, Traefik strategy, Java migration, repo)

## 次にやること

### 1. SqlStore (DAO trait + PostgreSQL) — 最優先

```rust
trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: &str) -> Result<Option<UserRecord>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>>;
    async fn create_or_update(&self, user: UserRecord) -> Result<()>;
}
// + TenantStore, MembershipStore, InvitationStore
// + SqlImpl (sqlx PostgreSQL)
```

Java 参照: `SqlStore.java`

### 2. Processor DB 配線

```
OidcInitProcessor    → idp.authorization_url()
TokenExchange        → idp.exchange_code()
UserResolve          → idp.userinfo() + UserStore
MfaVerify            → totp::verify_totp()
PasskeyVerify        → webauthn-rs
SessionIssue         → SessionStore.create() + jwt.issue()
```

### 3. Integration test (testcontainers + PostgreSQL)

### 4. Open issues: ACME DNS-01, Docker labels, Getting Started, README, benchmark article

### 5. SAML → Java sidecar (DD-005)
