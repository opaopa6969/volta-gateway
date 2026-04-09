# volta-gateway Backlog

> Last updated: 2026-04-09

## Completed

<details>
<summary>~110 items completed (click to expand)</summary>

**Day 1-3:** ~90 items (gateway features, tramli upgrade, auth-core Phase 0)

**Day 3+ (Java→Rust migration):**
- auth-core SqlStore (7 record types, 6 store traits, PgStore, 7 migrations)
- Processor DB 配線 (JwtIssuer, AuthService orchestrator)
- Integration test (testcontainers + PostgreSQL, 9 tests)
- FlowPersistence (auth_flows + transitions, optimistic lock)
- WebAuthn/Passkey (PasskeyService, webauthn-rs)
- Docker labels config source (bollard)
- Config source hot reload 統合 (ArcSwap merge)
- ACME DNS-01 (instant-acme + Cloudflare provider)
- SAML sidecar routing config
- E2E テスト追加 (gateway 8 integration tests)
- Benchmark 記事, Getting Started, README 更新

**Tests: 63** (auth-core 55 + gateway 8)
**Crates: 4** (gateway, auth-core, volta-bin, traefik-to-volta)
</details>

---

## Java 置き換えロードマップ

> Ref: [Gap Analysis](gap-analysis-java-rust.md) | [DD-005](../dge/decisions/DD-005-java-to-rust-migration.md)

### Phase 1: auth-server crate (HTTP API 基盤) 🔴 Critical

**目標:** gateway が Java auth-proxy の代わりに Rust auth-server を使えるようにする

| # | Item | エンドポイント | 依存 |
|---|------|--------------|------|
| P1-1 | auth-server crate 新設 (Axum) | — | — |
| P1-2 | /auth/verify エンドポイント | GET /auth/verify | SessionStore |
| P1-3 | OIDC login + callback | GET /login, GET /callback, POST /auth/callback/complete | AuthService.oidc_* |
| P1-4 | Logout | GET/POST /auth/logout | SessionStore.revoke |
| P1-5 | Token refresh | POST /auth/refresh | AuthService.token_refresh |
| P1-6 | Session API | GET/DELETE /api/me/sessions, DELETE /api/me/sessions/{id} | SessionStore |
| P1-7 | User profile | GET /api/v1/users/me, GET /api/v1/users/me/tenants | UserStore, TenantStore |
| P1-8 | JWKS | GET /.well-known/jwks.json | 署名鍵 |
| P1-9 | Health check | GET /healthz | — |
| P1-10 | sessions テーブル migration | — | SessionStore PG 実装 |

**完了条件:** `volta-gateway --auth-mode=rust` で Java auth-proxy なしで OIDC ログイン完了

### Phase 2: MFA + Magic Link + 署名鍵 🟠 High

| # | Item | エンドポイント | 依存 |
|---|------|--------------|------|
| P2-1 | MFA セットアップ (TOTP) | POST /api/v1/users/{id}/mfa/totp/setup, /verify | user_mfa テーブル |
| P2-2 | MFA リカバリコード | POST /regenerate, DELETE /totp | mfa_recovery_codes テーブル |
| P2-3 | MFA テナントポリシー + 猶予期間 | — | tenants.mfa_required, mfa_grace_until |
| P2-4 | MFA challenge + verify エンドポイント | GET /mfa/challenge, POST /auth/mfa/verify | — |
| P2-5 | Magic Link | POST /auth/magic-link/send, GET /verify | magic_links テーブル |
| P2-6 | 署名鍵 DB 保存 + ローテーション | POST /admin/keys/rotate, /revoke | signing_keys テーブル |
| P2-7 | Switch account/tenant | POST /auth/switch-account, /switch-tenant | — |

### Phase 3: マルチ IdP + M2M + Passkey DB 🟠 High

| # | Item | エンドポイント | 依存 |
|---|------|--------------|------|
| P3-1 | IdP 設定 DB 保存 | GET/POST /api/v1/tenants/{id}/idp-configs | idp_configs テーブル |
| P3-2 | マルチ IdP ルーティング (Google/GitHub/Microsoft) | /login?provider=github | IdpConfig → IdpClient |
| P3-3 | M2M クライアント | GET/POST /api/v1/tenants/{id}/m2m-clients | m2m_clients テーブル |
| P3-4 | OAuth2 token endpoint (M2M) | POST /oauth/token | client_credentials grant |
| P3-5 | Passkey DB 永続化 | CRUD /api/v1/users/{id}/passkeys | user_passkeys テーブル |
| P3-6 | Passkey 認証フロー endpoint | POST /auth/passkey/start, /finish | PasskeyService |
| P3-7 | User 管理 API | PATCH /api/v1/users/{id}, DELETE | — |
| P3-8 | Tenant 管理 API | POST /api/v1/tenants, PATCH, transfer-ownership | — |
| P3-9 | Member 管理 API | GET/PATCH/DELETE /api/v1/tenants/{id}/members/{id} | — |
| P3-10 | Invitation API | POST/GET/DELETE /api/v1/tenants/{id}/invitations | — |

### Phase 4: Webhook + Audit + GDPR 🟡 Medium

| # | Item | エンドポイント | 依存 |
|---|------|--------------|------|
| P4-1 | Webhook CRUD | GET/POST/PATCH/DELETE /api/v1/tenants/{id}/webhooks | webhook_subscriptions テーブル |
| P4-2 | Outbox パターン + Worker | POST /admin/outbox/flush | outbox_events テーブル |
| P4-3 | Webhook 配信 + リトライ | — | webhook_deliveries テーブル |
| P4-4 | Audit ログ (insert + list) | GET /api/v1/admin/audit | audit_logs テーブル |
| P4-5 | GDPR データエクスポート | POST /api/v1/users/me/data-export | — |
| P4-6 | GDPR hard delete + anonymize | DELETE /api/v1/users/{id}/data | audit anonymize |
| P4-7 | Device Trust | GET/DELETE /api/v1/users/me/devices | known_devices, trusted_devices テーブル |
| P4-8 | Security Policy (per-tenant) | — | tenant_security_policies テーブル |

### Phase 5: SCIM + Billing + Admin UI 🟢 Low

| # | Item | エンドポイント | 依存 |
|---|------|--------------|------|
| P5-1 | SCIM 2.0 Users | GET/POST/PUT/PATCH/DELETE /scim/v2/Users | — |
| P5-2 | SCIM 2.0 Groups | GET/POST /scim/v2/Groups | — |
| P5-3 | Plans + Subscriptions | GET /billing, POST /subscription | plans, subscriptions テーブル |
| P5-4 | Stripe Webhook | POST /api/v1/billing/stripe/webhook | — |
| P5-5 | Policy engine (DB) | GET/POST /api/v1/tenants/{id}/policies, /evaluate | policies テーブル |
| P5-6 | Admin HTML pages | GET /admin/{members,tenants,users,...} | テンプレートエンジン |
| P5-7 | Admin API (system) | GET /api/v1/admin/{tenants,users} | — |

### SAML (別トラック — DD-005)

DD-005 決定: SAML は Java sidecar (volta-auth-proxy) に維持。
gateway の `path_prefix: /saml/` + `public: true` で Java に転送。

将来的に samael (Rust) が成熟したら Rust ネイティブに移行検討。

---

## Open — GitHub Issues

| # | Issue | Status |
|---|-------|--------|
| #37 | Streaming compression | 🟡 Open |
| #39 | Access log file separation | 🟡 Open |
| #43 | ACME DNS-01 | ✅ Done (Phase 1+2) |
| #44 | Docker labels source | ✅ Done |
| #45 | Getting Started guide | ✅ Done |
| #46 | README messaging rewrite | ✅ Done |
| #47 | Benchmark article | ✅ Done |

## Open — Technical Debt

| # | Item | Severity |
|---|------|----------|
| CR-10 | HTTPS backend (mTLS module ready) | 🟡 Medium |
| GW-39 | proxy.rs 分割 (1,100行超) | 🟡 Medium |
| GW-41 | L4 proxy IP 制限 | 🟡 Medium |

## Design Decisions

- [DD-001](../dge/decisions/DD-001-cors-default-deny.md) — CORS デフォルトを deny に
- [DD-002](../dge/decisions/DD-002-l4-proxy-scope.md) — L4 proxy は認証対象外
- [DD-003](../dge/decisions/DD-003-accept-criteria.md) — v0.1.0 Accept 基準
- [DD-004](../dge/decisions/DD-004-traefik-user-acquisition.md) — Traefik ユーザー獲得戦略
- [DD-005](../dge/decisions/DD-005-java-to-rust-migration.md) — Java→Rust 段階的移行
- [DD-006](../dge/decisions/DD-006-auth-proxy-rs-repo.md) — auth-proxy-rs は Cargo workspace で同居
