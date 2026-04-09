# auth-server Phase 3 — マルチ IdP + M2M + Passkey DB + 管理 API

> Status: Spec
> Date: 2026-04-09
> Depends on: Phase 2

## 概要

複数 IdP (Google/GitHub/Microsoft) の DB 設定管理、
M2M (Service-to-Service) 認証、Passkey の DB 永続化、
User/Tenant/Member/Invitation 管理 API の充実。

## P3-1: IdP 設定 DB 保存

### テーブル

```sql
CREATE TABLE idp_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    provider_type VARCHAR(32) NOT NULL,  -- google, github, microsoft, saml
    metadata_url TEXT,
    issuer TEXT,
    client_id TEXT,
    client_secret TEXT,                  -- encrypted at rest
    x509_cert TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active BOOLEAN NOT NULL DEFAULT true
);
```

### Store trait

```rust
#[async_trait]
pub trait IdpConfigStore: Send + Sync {
    async fn upsert(&self, config: IdpConfigRecord) -> Result<Uuid, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<IdpConfigRecord>, AuthError>;
    async fn find(&self, tenant_id: Uuid, provider_type: &str) -> Result<Option<IdpConfigRecord>, AuthError>;
}
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/tenants/{id}/idp-configs | テナントの IdP 設定一覧 |
| POST | /api/v1/tenants/{id}/idp-configs | IdP 設定登録/更新 |

### マルチ IdP ルーティング

```
GET /login?provider=github&tenant=acme
  → IdpConfigStore.find(tenant_id, "github")
  → IdpClient::new(config) で provider 別クライアント生成
  → authorization_url() → redirect
```

## P3-2: M2M クライアント (Service Auth)

### テーブル

```sql
CREATE TABLE m2m_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    client_id VARCHAR(120) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Store trait

```rust
#[async_trait]
pub trait M2mClientStore: Send + Sync {
    async fn create(&self, record: M2mClientRecord) -> Result<Uuid, AuthError>;
    async fn find(&self, client_id: &str) -> Result<Option<M2mClientRecord>, AuthError>;
    async fn list_by_tenant(&self, tenant_id: Uuid) -> Result<Vec<M2mClientRecord>, AuthError>;
}
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/tenants/{id}/m2m-clients | M2M client 作成 (client_id + secret 発行) |
| GET | /api/v1/tenants/{id}/m2m-clients | M2M client 一覧 |
| POST | /oauth/token | client_credentials grant → JWT 発行 |

### Token 発行フロー

```
POST /oauth/token
  grant_type=client_credentials
  client_id=xxx
  client_secret=yyy
→ M2mClientStore.find(client_id)
→ bcrypt verify secret
→ JwtIssuer.issue(claims: { sub: client_id, tenant_id, scopes })
→ { access_token, token_type: "Bearer", expires_in: 3600 }
```

## P3-3: Passkey DB 永続化

### テーブル

```sql
CREATE TABLE user_passkeys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT,
    name VARCHAR(64),
    aaguid UUID,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ
);
```

### Store trait

```rust
#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn create(&self, record: PasskeyRecord) -> Result<Uuid, AuthError>;
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<PasskeyRecord>, AuthError>;
    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<PasskeyRecord>, AuthError>;
    async fn update_counter(&self, id: Uuid, sign_count: i64) -> Result<(), AuthError>;
    async fn delete(&self, user_id: Uuid, id: Uuid) -> Result<(), AuthError>;
    async fn count(&self, user_id: Uuid) -> Result<usize, AuthError>;
}
```

### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/users/{id}/passkeys/register/start | 登録 challenge 生成 |
| POST | /api/v1/users/{id}/passkeys/register/finish | 登録完了 → DB 保存 |
| GET | /api/v1/users/{id}/passkeys | passkey 一覧 |
| DELETE | /api/v1/users/{id}/passkeys/{id} | passkey 削除 |
| POST | /auth/passkey/start | 認証 challenge 生成 |
| POST | /auth/passkey/finish | 認証検証 → セッション作成 |

## P3-4〜10: 管理 API

### User 管理

| Method | Path | 説明 |
|--------|------|------|
| PATCH | /api/v1/users/{id} | display_name 更新 |
| PATCH | /api/v1/users/{id}/locale | locale 更新 |
| DELETE | /api/v1/users/me | アカウント削除 (soft delete) |

### Tenant 管理

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/tenants | テナント作成 |
| PATCH | /api/v1/tenants/{id} | テナント設定更新 |
| POST | /api/v1/tenants/{id}/transfer-ownership | オーナー移譲 |

### Member 管理

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/tenants/{id}/members | メンバー一覧 |
| GET | /api/v1/tenants/{id}/members/{id} | メンバー詳細 |
| PATCH | /api/v1/tenants/{id}/members/{id} | ロール変更 |
| DELETE | /api/v1/tenants/{id}/members/{id} | メンバー削除 |

### Invitation 管理

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/tenants/{id}/invitations | 招待作成 |
| GET | /api/v1/tenants/{id}/invitations | 招待一覧 |
| DELETE | /api/v1/tenants/{id}/invitations/{id} | 招待キャンセル |
| GET | /invite/{code} | 招待受諾画面 |
| POST | /invite/{code}/accept | 招待受諾 |

## テスト

- マルチ IdP: tenant A = Google, tenant B = GitHub → 各プロバイダーで OIDC login
- M2M: create client → POST /oauth/token → verify JWT
- Passkey: register → authenticate → counter update → delete
- 管理 API: CRUD 操作 + 権限チェック (OWNER only for delete)
