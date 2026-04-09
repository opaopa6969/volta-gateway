# volta-auth-core

認証ライブラリ — JWT, セッション, OIDC/MFA/Passkey フロー, DAO traits + PostgreSQL。

## 概要

auth-core は auth-server と gateway の両方が使う共有ライブラリです。HTTP 層を持たず、ビジネスロジックとデータアクセスのみ。

## モジュール

| モジュール | 用途 |
|-----------|------|
| `jwt` | JWT 検証 (JwtVerifier) + 発行 (JwtIssuer) — HS256, RSA |
| `session` | Cookie → JWT → X-Volta-* ヘッダー変換 |
| `store` | 15 の DAO traits + InMemorySessionStore |
| `store::pg` | PostgreSQL 実装 (sqlx, `postgres` feature) |
| `record` | 20+ レコード型 (User, Tenant, Membership, Session, ...) |
| `policy` | RBAC ポリシーエンジン |
| `flow` | tramli SM フロー (OIDC, MFA, Passkey, Invite, Token) |
| `service` | async オーケストレーター (AuthService) |
| `idp` | OAuth2/OIDC クライアント (Google, GitHub, Microsoft, LinkedIn, Apple) |
| `totp` | TOTP 検証 + シークレット生成 |
| `passkey` | WebAuthn/Passkey (webauthn-rs, `webauthn` feature) |

## Store Traits (15)

| Trait | メソッド数 |
|-------|----------|
| SessionStore | 9 |
| UserStore | 6 |
| TenantStore | 5 |
| MembershipStore | 6 |
| InvitationStore | 5 |
| FlowPersistence | 7 |
| MfaStore | 4 |
| RecoveryCodeStore | 4 |
| MagicLinkStore | 2 |
| SigningKeyStore | 5 |
| IdpConfigStore | 3 |
| M2mClientStore | 3 |
| PasskeyStore | 6 |
| WebhookStore / OutboxStore / WebhookDeliveryStore | 12 |
| AuditStore / DeviceTrustStore / BillingStore / PolicyStore | 13 |

## Features

```toml
[features]
postgres = ["sqlx"]     # PostgreSQL 実装
webauthn = ["webauthn-rs"]  # WebAuthn/Passkey
```

## テスト

```bash
# ユニットテスト (46 tests)
cargo test -p volta-auth-core

# PostgreSQL integration テスト (9 tests, Docker 必要)
cargo test -p volta-auth-core --features postgres -- --ignored
```

## マイグレーション

`auth-core/migrations/` に 20 SQL ファイル:

```
001_create_users.sql         008_create_sessions.sql       015_create_user_passkeys.sql
002_create_tenants.sql       009_create_user_mfa.sql       016_create_webhooks.sql
003_create_memberships.sql   010_create_mfa_recovery_codes.sql  017_create_audit_logs.sql
004_create_invitations.sql   011_create_magic_links.sql     018_create_devices.sql
005_create_invitation_usages.sql  012_create_signing_keys.sql   019_create_billing.sql
006_create_auth_flows.sql    013_create_idp_configs.sql     020_create_policies.sql
007_create_auth_flow_transitions.sql  014_create_m2m_clients.sql
```
