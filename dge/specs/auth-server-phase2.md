# auth-server Phase 2 — MFA + Magic Link + 署名鍵

> Status: Spec
> Date: 2026-04-09
> Depends on: Phase 1 (auth-server HTTP 基盤)

## 概要

MFA (TOTP セットアップ + リカバリコード + テナントポリシー)、
Magic Link (パスワードレス認証)、署名鍵 DB 管理 + ローテーション。

## P2-1: MFA セットアップ (TOTP)

### 新規テーブル

```sql
CREATE TABLE user_mfa (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    type VARCHAR(20) NOT NULL,        -- 'totp', 'email'
    secret TEXT NOT NULL,              -- encrypted TOTP secret
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Store trait

```rust
#[async_trait]
pub trait MfaStore: Send + Sync {
    async fn upsert(&self, user_id: Uuid, mfa_type: &str, secret: &str) -> Result<(), AuthError>;
    async fn find(&self, user_id: Uuid, mfa_type: &str) -> Result<Option<MfaRecord>, AuthError>;
    async fn has_active(&self, user_id: Uuid) -> Result<bool, AuthError>;
    async fn deactivate(&self, user_id: Uuid, mfa_type: &str) -> Result<(), AuthError>;
}
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/users/{id}/mfa/totp/setup | TOTP secret 生成 → QR URI 返却 |
| POST | /api/v1/users/{id}/mfa/totp/verify | セットアップ時の初回コード検証 → 有効化 |
| DELETE | /api/v1/users/{id}/mfa/totp | TOTP 無効化 |
| GET | /api/v1/users/me/mfa | MFA ステータス (enabled, type, recovery codes 残数) |

### セットアップフロー

```
1. POST /mfa/totp/setup → { secret: "BASE32...", uri: "otpauth://totp/..." }
2. ユーザーが Authenticator アプリに登録
3. POST /mfa/totp/verify { code: "123456" } → totp::verify_totp() で検証
4. 成功 → user_mfa に INSERT → recovery codes 生成
```

## P2-2: MFA リカバリコード

### テーブル

```sql
CREATE TABLE mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    code_hash VARCHAR(128) NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, code_hash)
);
```

### Store trait

```rust
#[async_trait]
pub trait RecoveryCodeStore: Send + Sync {
    async fn replace_all(&self, user_id: Uuid, code_hashes: &[String]) -> Result<(), AuthError>;
    async fn consume(&self, user_id: Uuid, code_hash: &str) -> Result<bool, AuthError>;
    async fn count_unused(&self, user_id: Uuid) -> Result<usize, AuthError>;
    async fn delete_all(&self, user_id: Uuid) -> Result<(), AuthError>;
}
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/users/{id}/mfa/recovery-codes/regenerate | 新しいコードセット生成 (10個) |

## P2-3: MFA テナントポリシー

tenants テーブルの `mfa_required`, `mfa_grace_until` フィールドを活用。
OIDC callback 時に `mfa_required && !session.mfa_verified` → MFA challenge に遷移。

## P2-4: MFA Challenge エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| GET | /mfa/challenge | MFA challenge ページ (HTML or JSON) |
| POST | /auth/mfa/verify | TOTP コード検証 → session MFA flag 更新 |

## P2-5: Magic Link

### テーブル

```sql
CREATE TABLE magic_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    token VARCHAR(128) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /auth/magic-link/send | email → token 生成 → メール送信 (hook) |
| GET | /auth/magic-link/verify?token=xxx | token 消費 → セッション作成 |

**メール送信:** trait `EmailSender` で抽象化。実装は外部 (SendGrid, SES, SMTP)。

```rust
#[async_trait]
pub trait EmailSender: Send + Sync {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), String>;
}
```

## P2-6: 署名鍵管理

### テーブル

```sql
CREATE TABLE signing_keys (
    kid VARCHAR(64) PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,   -- encrypted at rest
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
```

### Store trait

```rust
#[async_trait]
pub trait SigningKeyStore: Send + Sync {
    async fn save(&self, kid: &str, public_pem: &str, private_pem: &str) -> Result<(), AuthError>;
    async fn load_active(&self) -> Result<Option<SigningKeyRecord>, AuthError>;
    async fn list(&self) -> Result<Vec<SigningKeyMeta>, AuthError>;
    async fn rotate(&self, old_kid: &str, new_kid: &str, pub_key: &str, priv_key: &str) -> Result<(), AuthError>;
    async fn revoke(&self, kid: &str) -> Result<(), AuthError>;
}
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/admin/keys | 鍵一覧 (kid, status, created_at) |
| POST | /api/v1/admin/keys/rotate | 新鍵生成 → 旧鍵 retired |
| POST | /api/v1/admin/keys/{kid}/revoke | 鍵失効 |

### JWKS 連動

`/.well-known/jwks.json` は signing_keys テーブルの active 鍵から動的生成。

## P2-7: Switch Account/Tenant

| Method | Path | 説明 |
|--------|------|------|
| POST | /auth/switch-account | 別ユーザーに切り替え (re-auth) |
| POST | /auth/switch-tenant | 同ユーザーの別テナントに切り替え |
| GET | /select-tenant | テナント選択画面 |

## テスト

- MFA: setup → verify → login with TOTP → recovery code → disable
- Magic Link: send → consume → session created
- 署名鍵: rotate → old key invalid → new key works → JWKS updated
