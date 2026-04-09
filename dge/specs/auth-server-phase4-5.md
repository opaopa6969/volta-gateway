# auth-server Phase 4-5 — Webhook/Audit/GDPR + SCIM/Billing/Admin

> Status: Spec
> Date: 2026-04-09
> Depends on: Phase 3

---

## Phase 4: Webhook + Audit + GDPR + Device Trust

### P4-1: Webhook CRUD

#### テーブル

```sql
CREATE TABLE webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    endpoint_url TEXT NOT NULL,
    secret VARCHAR(255) NOT NULL,      -- HMAC 署名用
    events TEXT NOT NULL,              -- CSV: "user.created,member.added"
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    outbox_event_id UUID NOT NULL REFERENCES outbox_events(id),
    webhook_id UUID NOT NULL REFERENCES webhook_subscriptions(id),
    event_type VARCHAR(80) NOT NULL,
    status VARCHAR(20) NOT NULL,       -- pending, success, failed
    status_code INT,
    response_body TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/tenants/{id}/webhooks | Webhook 登録 |
| GET | /api/v1/tenants/{id}/webhooks | Webhook 一覧 |
| GET | /api/v1/tenants/{id}/webhooks/{id} | Webhook 詳細 |
| PATCH | /api/v1/tenants/{id}/webhooks/{id} | Webhook 更新 |
| DELETE | /api/v1/tenants/{id}/webhooks/{id} | Webhook 削除 |
| GET | /api/v1/tenants/{id}/webhooks/{id}/deliveries | 配信ログ |

### P4-2: Outbox パターン

#### テーブル

```sql
CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    event_type VARCHAR(80) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,
    attempt_count INT DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT now(),
    last_error TEXT
);
```

#### Worker

```rust
pub struct OutboxWorker {
    db: PgStore,
    http: reqwest::Client,
    poll_interval: Duration,
}

impl OutboxWorker {
    /// Poll pending events, deliver to matching webhooks, record results.
    pub async fn run(&self) {
        loop {
            let events = self.db.claim_pending(10, "worker-1", 60).await;
            for event in events {
                let webhooks = self.db.find_matching_webhooks(event.tenant_id, &event.event_type).await;
                for wh in webhooks {
                    let result = self.deliver(&wh, &event).await;
                    self.db.record_delivery(event.id, wh.id, &result).await;
                }
                self.db.mark_published(event.id).await;
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// HMAC-SHA256 署名付き POST
    async fn deliver(&self, webhook: &WebhookRecord, event: &OutboxRecord) -> DeliveryResult { ... }
}
```

### P4-3: Audit ログ

#### テーブル

```sql
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type VARCHAR(50) NOT NULL,   -- user.login, member.added, tenant.created, ...
    actor_id UUID,
    actor_ip INET,
    tenant_id UUID,
    target_type VARCHAR(30),           -- user, tenant, member, session
    target_id VARCHAR(255),
    detail JSONB,
    request_id UUID NOT NULL
);
```

#### Service

```rust
pub struct AuditService {
    db: PgStore,
}

impl AuditService {
    pub async fn log(&self, event: AuditEvent) -> Result<(), AuthError>;
    pub async fn list(&self, tenant_id: Uuid, offset: i64, limit: i64) -> Result<Vec<AuditLog>, AuthError>;
    pub async fn anonymize(&self, user_id: Uuid) -> Result<(), AuthError>;
}
```

#### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/admin/audit | Audit ログ一覧 (admin) |

#### 挿入ポイント

各 handler の成功時に `AuditService::log()` を呼ぶ:
- `user.login` — OIDC callback 成功時
- `user.logout` — logout 時
- `member.added` — invitation accept 時
- `member.removed` — member delete 時
- `tenant.created` — tenant create 時
- etc.

### P4-4: GDPR

#### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/users/me/data-export | JSON でユーザーデータ一括エクスポート |
| POST | /api/v1/users/{id}/export | Admin: ユーザーデータエクスポート |
| DELETE | /api/v1/users/{id}/data | Admin: hard delete (全データ削除) |

#### データエクスポート

```json
{
  "user": { "id": "...", "email": "...", "display_name": "..." },
  "tenants": [...],
  "memberships": [...],
  "sessions": [...],
  "audit_logs": [...],
  "devices": [...]
}
```

#### Hard Delete フロー

```
1. soft_delete(user_id) → users.deleted_at = now()
2. 30日後: findUsersToHardDelete(30)
3. hardDeleteUser(user_id):
   - DELETE mfa_recovery_codes WHERE user_id = ?
   - DELETE user_mfa WHERE user_id = ?
   - DELETE sessions WHERE user_id = ?
   - DELETE memberships WHERE user_id = ?
   - anonymizeAuditLogs(user_id)  -- actor_id = NULL, detail = NULL
   - DELETE users WHERE id = ?
```

### P4-5: Device Trust

#### テーブル

```sql
CREATE TABLE known_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    fingerprint VARCHAR(128) NOT NULL,
    label VARCHAR(64),
    last_ip TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, fingerprint)
);

CREATE TABLE trusted_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID NOT NULL,
    device_name VARCHAR(100),
    user_agent VARCHAR(500),
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tenant_security_policies (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    new_device_action VARCHAR(20) NOT NULL DEFAULT 'notify',
    risk_action_threshold INT NOT NULL DEFAULT 4,
    risk_block_threshold INT NOT NULL DEFAULT 5,
    notify_user BOOLEAN NOT NULL DEFAULT true,
    notify_admin BOOLEAN NOT NULL DEFAULT false,
    auto_trust_passkey BOOLEAN NOT NULL DEFAULT true,
    max_trusted_devices INT NOT NULL DEFAULT 10,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### エンドポイント

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/users/me/devices | 信頼済みデバイス一覧 |
| DELETE | /api/v1/users/me/devices/{id} | デバイス削除 |
| DELETE | /api/v1/users/me/devices | 全デバイス削除 |

---

## Phase 5: SCIM + Billing + Policy + Admin UI

### P5-1/2: SCIM 2.0

| Method | Path | 説明 |
|--------|------|------|
| GET | /scim/v2/Users | ユーザー一覧 (filter, pagination) |
| POST | /scim/v2/Users | ユーザー作成 |
| GET | /scim/v2/Users/{id} | ユーザー詳細 |
| PUT | /scim/v2/Users/{id} | ユーザー置換 |
| PATCH | /scim/v2/Users/{id} | ユーザー部分更新 |
| DELETE | /scim/v2/Users/{id} | ユーザー削除 |
| GET | /scim/v2/Groups | グループ一覧 |
| POST | /scim/v2/Groups | グループ作成 |

SCIM 2.0 (RFC 7644) 準拠。テナント単位で Bearer token 認証。

### P5-3/4: Billing

#### テーブル

```sql
CREATE TABLE plans (
    id VARCHAR(30) PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    max_members INT NOT NULL,
    max_apps INT NOT NULL,
    features TEXT NOT NULL DEFAULT ''
);

CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    plan_id VARCHAR(30) NOT NULL REFERENCES plans(id),
    status VARCHAR(20) NOT NULL,       -- active, canceled, past_due
    stripe_sub_id VARCHAR(255),
    started_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ
);
```

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/tenants/{id}/billing | プラン + サブスクリプション情報 |
| POST | /api/v1/tenants/{id}/billing/subscription | サブスクリプション作成/変更 |
| POST | /api/v1/billing/stripe/webhook | Stripe webhook receiver |

### P5-5: Policy Engine (DB)

```sql
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    condition JSONB NOT NULL DEFAULT '{}'::jsonb,
    effect VARCHAR(10) NOT NULL DEFAULT 'allow',
    priority INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/tenants/{id}/policies | ポリシー一覧 |
| POST | /api/v1/tenants/{id}/policies | ポリシー作成 |
| POST | /api/v1/tenants/{id}/policies/evaluate | ポリシーテスト評価 |

### P5-6: Admin HTML ページ

テンプレートエンジン (askama or tera) で HTML 管理画面:

| Path | 説明 |
|------|------|
| /admin/members | メンバー管理 |
| /admin/invitations | 招待管理 |
| /admin/webhooks | Webhook 管理 |
| /admin/idp | IdP 設定 |
| /admin/tenants | テナント管理 |
| /admin/users | ユーザー管理 |
| /admin/sessions | セッション管理 |
| /admin/audit | 監査ログ |

### P5-7: Admin API (System)

| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/admin/tenants | テナント一覧 (system admin) |
| POST | /api/v1/admin/tenants/{id}/suspend | テナント停止 |
| POST | /api/v1/admin/tenants/{id}/activate | テナント有効化 |
| GET | /api/v1/admin/users | ユーザー一覧 (system admin) |
| POST | /api/v1/admin/outbox/flush | Outbox 強制配信 |

---

## 全 Phase テーブル一覧

| Phase | テーブル |
|-------|---------|
| 1 | sessions (migration 追加) |
| 2 | user_mfa, mfa_recovery_codes, magic_links, signing_keys |
| 3 | idp_configs, m2m_clients, user_passkeys |
| 4 | webhook_subscriptions, webhook_deliveries, outbox_events, audit_logs, known_devices, trusted_devices, tenant_security_policies |
| 5 | plans, subscriptions, policies |

合計: 14 テーブル追加 (既存 7 + 新規 14 = 21 テーブル = Java 版と同数)
