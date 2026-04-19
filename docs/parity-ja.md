[English version](parity.md)

# Rust ↔ Java 機能パリティ

> **範囲:** `auth-server` (Rust) の全ルートと Java `volta-auth-proxy` の対応関係。
> gateway 側のみの機能 (リバースプロキシ、プラグイン、L4 proxy、TLS/ACME) は
> 末尾にまとめて記載。
>
> **目的:** Rust 側が Java と同じ**表面**を提供することで、`volta-bin` から
> Java sidecar を外してもクライアント側に見える変化がないこと。

凡例:

| 記号  | 意味                                                           |
|-------|----------------------------------------------------------------|
| ✅    | 両側で実装済、動作確認済                                      |
| ⚠️    | 実装済だが注記あり (Notes 列参照)                             |
| 🚧    | 一部実装 (ルート存在するが機能縮小)                           |
| ⏸    | 見送り — Java は持つが Rust は意図的に未実装                  |
| —     | 該当なし (gateway 専用 / auth-proxy 専用)                     |

---

## ルートパリティ (auth-server ~96 エンドポイント)

一覧は `auth-server/src/app.rs` から抽出。Method 列はマウント時の Axum メソッド。

### 認証ライフサイクル

| Method | Path                              | Rust | Java | 注記 |
|--------|-----------------------------------|:----:|:----:|------|
| GET    | `/auth/verify`                    | ✅   | ✅   | ForwardAuth。local-bypass → MFA-pending → tenant-suspend の順序は AUTH-010 準拠 |
| GET    | `/auth/logout`                    | ✅   | ✅   | — |
| POST   | `/auth/logout`                    | ✅   | ✅   | — |
| POST   | `/auth/refresh`                   | ✅   | ✅   | — |
| POST   | `/auth/switch-tenant`             | ✅   | ✅   | MFA state リセット (`mfa_verified_at: None`) — Java #12 |
| POST   | `/auth/switch-account`            | ✅   | ✅   | — |
| GET    | `/select-tenant`                  | ✅   | ✅   | — |

### OIDC (レート制限 10/min/IP)

| Method | Path                              | Rust | Java | 注記 |
|--------|-----------------------------------|:----:|:----:|------|
| GET    | `/login`                          | ✅   | ✅   | — |
| GET    | `/callback`                       | ✅   | ✅   | Rust は HMAC 署名 state (stateless)、Java は `consume_oidc_flow` atomic delete |
| POST   | `/auth/callback/complete`         | ✅   | ✅   | — |

### SAML

| Method | Path                              | Rust | Java | 注記 |
|--------|-----------------------------------|:----:|:----:|------|
| GET    | `/auth/saml/login`                | ✅   | ✅   | — |
| POST   | `/auth/saml/callback`             | ⚠️   | ✅   | 0.3.0 で XML-DSig 経路投入済だが、本番 SAML は DD-005 に従い Java sidecar (`path_prefix: /saml/`) 推奨 |

### MFA (TOTP + Magic Link)

| Method | Path                                                              | Rust | Java | 注記 |
|--------|-------------------------------------------------------------------|:----:|:----:|------|
| POST   | `/api/v1/users/{userId}/mfa/totp/setup`                           | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/mfa/totp/verify`                          | ✅   | ✅   | — |
| DELETE | `/api/v1/users/{userId}/mfa/totp`                                 | ✅   | ✅   | — |
| GET    | `/api/v1/users/me/mfa`                                            | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/mfa/recovery-codes/regenerate`            | ✅   | ✅   | — |
| GET    | `/mfa/challenge`                                                  | ✅   | ✅   | HTML TOTP 入力 (AUTH-010) |
| POST   | `/auth/mfa/verify`                                                | ✅   | ✅   | レート 5/min/IP |
| POST   | `/auth/magic-link/send`                                           | ✅   | ✅   | レート 5/min/IP |
| GET    | `/auth/magic-link/verify`                                         | ✅   | ✅   | レート 5/min/IP |

### Passkey (WebAuthn)

| Method | Path                                                              | Rust | Java | 注記 |
|--------|-------------------------------------------------------------------|:----:|:----:|------|
| POST   | `/auth/passkey/start`                                             | ✅   | ✅   | レート 5/min/IP |
| POST   | `/auth/passkey/finish`                                            | ✅   | ✅   | レート 5/min/IP |
| POST   | `/api/v1/users/{userId}/passkeys/register/start`                  | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/passkeys/register/finish`                 | ✅   | ✅   | — |
| GET    | `/api/v1/users/{userId}/passkeys`                                 | ✅   | ✅   | — |
| DELETE | `/api/v1/users/{userId}/passkeys/{passkeyId}`                     | ✅   | ✅   | sign counter atomic UPDATE (Java #17) |

### セッション

| Method | Path                                        | Rust | Java | 注記 |
|--------|---------------------------------------------|:----:|:----:|------|
| GET    | `/api/me/sessions`                          | ✅   | ✅   | — |
| DELETE | `/api/me/sessions`                          | ✅   | ✅   | 全取消 |
| DELETE | `/api/me/sessions/{id}`                     | ✅   | ✅   | — |
| DELETE | `/auth/sessions/{id}`                       | ✅   | ✅   | — |
| POST   | `/auth/sessions/revoke-all`                 | ✅   | ✅   | — |
| GET    | `/admin/sessions`                           | ✅   | ✅   | — |
| DELETE | `/admin/sessions/{id}`                      | ✅   | ✅   | — |

### ユーザ profile + admin users

| Method | Path                                        | Rust | Java | 注記 |
|--------|---------------------------------------------|:----:|:----:|------|
| GET    | `/api/v1/users/me`                          | ✅   | ✅   | — |
| GET    | `/api/v1/users/me/tenants`                  | ✅   | ✅   | — |
| PATCH  | `/api/v1/users/{userId}`                    | ✅   | ✅   | — |
| DELETE | `/api/v1/users/me`                          | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/export`             | ✅   | ✅   | — |

### Tenant / Member / Invitation

| Method | Path                                                   | Rust | Java | 注記 |
|--------|--------------------------------------------------------|:----:|:----:|------|
| POST   | `/api/v1/tenants`                                      | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}`                           | ✅   | ✅   | — |
| PATCH  | `/api/v1/tenants/{tenantId}`                           | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/transfer-ownership`        | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/members`                   | ✅   | ✅   | ページング (`?page=&size=&sort=&q=`) |
| PATCH  | `/api/v1/tenants/{tenantId}/members/{memberId}`        | ✅   | ✅   | — |
| DELETE | `/api/v1/tenants/{tenantId}/members/{memberId}`        | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/invitations`               | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/invitations`               | ✅   | ✅   | ページング |
| DELETE | `/api/v1/tenants/{tenantId}/invitations/{invitationId}`| ✅   | ✅   | — |
| POST   | `/invite/{code}/accept`                                | ✅   | ✅   | レート 20/min/IP、NFC email 正規化 (Java #14) |

### IdP / M2M / OAuth2 token

| Method | Path                                                   | Rust | Java | 注記 |
|--------|--------------------------------------------------------|:----:|:----:|------|
| GET    | `/api/v1/tenants/{tenantId}/idp-configs`               | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/idp-configs`               | ✅   | ✅   | upsert |
| GET    | `/api/v1/tenants/{tenantId}/m2m-clients`               | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/m2m-clients`               | ✅   | ✅   | — |
| POST   | `/oauth/token`                                         | ✅   | ✅   | `client_credentials`、定数時間比較 (Java #21) |

### Webhook (Outbox パターン)

| Method | Path                                                               | Rust | Java | 注記 |
|--------|--------------------------------------------------------------------|:----:|:----:|------|
| POST   | `/api/v1/tenants/{tenantId}/webhooks`                              | ✅   | ✅   | SSRF ガード: HTTPS のみ + private IP reject (Java #1) |
| GET    | `/api/v1/tenants/{tenantId}/webhooks`                              | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}`                  | ✅   | ✅   | — |
| PATCH  | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}`                  | ✅   | ✅   | — |
| DELETE | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}`                  | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}/deliveries`       | ✅   | ✅   | — |

### Audit / Device / Billing / Policy / GDPR

| Method | Path                                                          | Rust | Java | 注記 |
|--------|---------------------------------------------------------------|:----:|:----:|------|
| GET    | `/api/v1/admin/audit`                                         | ✅   | ✅   | ページング (`?page=&size=&from=&to=&event=`) |
| GET    | `/api/v1/users/me/devices`                                    | ✅   | ✅   | — |
| DELETE | `/api/v1/users/me/devices/{deviceId}`                         | ✅   | ✅   | — |
| DELETE | `/api/v1/users/me/devices`                                    | ✅   | ✅   | 全件 |
| GET    | `/api/v1/tenants/{tenantId}/billing`                          | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/billing/subscription`             | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/policies`                         | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/policies`                         | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/policies/evaluate`                | ✅   | ✅   | — |
| POST   | `/api/v1/users/me/data-export`                                | ✅   | ✅   | — |
| DELETE | `/api/v1/users/{userId}/data`                                 | ✅   | ✅   | ハード削除拡張 (outbox_events + auth_flow_transitions, Java #18) |

### Admin (system)

| Method | Path                                                          | Rust | Java | 注記 |
|--------|---------------------------------------------------------------|:----:|:----:|------|
| GET    | `/api/v1/admin/tenants`                                       | ✅   | ✅   | — |
| GET    | `/api/v1/admin/users`                                         | ✅   | ✅   | ページング |
| GET    | `/api/v1/admin/sessions`                                      | ✅   | ✅   | ページング |
| POST   | `/api/v1/admin/outbox/flush`                                  | ✅   | ✅   | — |
| GET    | `/api/v1/admin/keys`                                          | ✅   | ✅   | — |
| POST   | `/api/v1/admin/keys/rotate`                                   | ✅   | ✅   | — |
| POST   | `/api/v1/admin/keys/{kid}/revoke`                             | ✅   | ✅   | — |
| GET    | `/admin/members`                                              | 🚧   | ✅   | HTML stub |
| GET    | `/admin/invitations`                                          | 🚧   | ✅   | HTML stub |
| GET    | `/admin/webhooks`                                             | 🚧   | ✅   | HTML stub |
| GET    | `/admin/idp`                                                  | 🚧   | ✅   | HTML stub |
| GET    | `/admin/tenants`                                              | 🚧   | ✅   | HTML stub |
| GET    | `/admin/users`                                                | 🚧   | ✅   | HTML stub |
| GET    | `/admin/audit`                                                | 🚧   | ✅   | HTML stub |
| GET    | `/settings/security`                                          | 🚧   | ✅   | HTML stub |
| GET    | `/settings/sessions`                                          | 🚧   | ✅   | HTML stub |

### SCIM 2.0

| Method | Path                                                  | Rust | Java | 注記 |
|--------|-------------------------------------------------------|:----:|:----:|------|
| GET    | `/scim/v2/Users`                                      | ✅   | ✅   | — |
| POST   | `/scim/v2/Users`                                      | ✅   | ✅   | — |
| GET    | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| PUT    | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| PATCH  | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| DELETE | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| GET    | `/scim/v2/Groups`                                     | ✅   | ✅   | — |
| POST   | `/scim/v2/Groups`                                     | ✅   | ✅   | — |

### 可視化 + ヘルス

| Method | Path                                                  | Rust | Java | 注記 |
|--------|-------------------------------------------------------|:----:|:----:|------|
| GET    | `/viz/auth/stream`                                    | ✅   | ✅   | SSE via Redis pub/sub (`auth_events::AuthEventBus`) |
| GET    | `/viz/flows`                                          | ✅   | ✅   | tramli-viz 一覧 |
| GET    | `/api/v1/admin/flows/{flowId}/transitions`            | ✅   | ✅   | — |
| GET    | `/healthz`                                            | ✅   | ✅   | — |
| GET    | `/.well-known/jwks.json`                              | ✅   | ✅   | 署名鍵ローテ対応 |

---

## gateway 機能パリティ (gateway crate vs Traefik / Java sidecar)

| 機能                                         | volta-gateway | Java `volta-auth-proxy` sidecar | 注記 |
|----------------------------------------------|:-------------:|:-------------------------------:|------|
| HTTP/1.1 + HTTP/2                            | ✅            | ✅ (nginx 経由)                 | hyper 自動ネゴ |
| WebSocket tunnel                             | ✅            | ✅                              | 1024 接続 |
| TLS + Let's Encrypt (TLS-ALPN-01)            | ✅            | — (nginx)                       | rustls-acme |
| Let's Encrypt DNS-01 (Cloudflare)            | ✅            | —                               | instant-acme |
| ラウンドロビン / 重み付き LB                 | ✅            | —                               | — |
| サーキットブレーカー                         | ✅            | ✅                              | 5 fails / 30s、Retry-After |
| 認証キャッシュ                               | ✅            | ✅                              | 5s TTL cookie ベース |
| gzip / brotli 圧縮                           | ✅            | ✅ (nginx)                      | streaming |
| CORS (per-route、secure-by-default)          | ✅            | ⚠️                              | Java は permissive 既定、Rust は DD-001 に従い deny |
| カスタムエラーページ                         | ✅            | ✅                              | — |
| ホットリロード (SIGHUP + `/admin/reload`)    | ✅            | ⚠️                              | Rust は `ArcSwap` ゼロダウンタイム |
| パブリックルート / `auth_bypass_paths`       | ✅            | ✅                              | — |
| `strip_prefix` / `add_prefix`                | ✅            | ✅                              | — |
| ヘッダ add/remove (per route)                | ✅            | ✅                              | — |
| トラフィックミラーリング                     | ✅            | —                               | fire-and-forget、`sample_rate` |
| 地理アクセス制御 (CF-IPCountry)              | ✅            | —                               | — |
| ルート別タイムアウト                         | ✅            | —                               | `timeout_secs` |
| W3C `traceparent` 伝搬                       | ✅            | ✅                              | — |
| レスポンスキャッシュ (LRU + TTL)             | ✅            | —                               | `X-Volta-Cache: HIT/MISS` |
| プラグインシステム (ネイティブ Rust)         | ✅            | —                               | `ApiKeyAuth`, `RateLimitByUser`, `Monetizer`, `HeaderInjector` |
| プラグイン (Wasm)                            | ⏸            | —                               | Phase 2 backlog |
| Config source (YAML + services.json + Docker labels + HTTP poll) | ✅ | — | hot-reload は `ArcSwap` マージ |
| Backend ヘルスチェック                       | ✅            | —                               | — |
| mTLS backend                                 | ✅            | —                               | — |
| グローバルバックプレッシャ (`Semaphore`)     | ✅            | —                               | — |
| Admin API (`/admin/{routes,backends,stats,reload,drain}`) | ✅ | —                       | localhost 限定 |
| `--validate` 設定検証                        | ✅            | —                               | CI/CD |
| L4 proxy (TCP/UDP)                           | ✅            | —                               | DD-002: 認証対象外 |
| Prometheus `/metrics`                        | ✅            | ✅                              | 8 bucket ヒストグラム |
| trusted proxy (CF-Connecting-IP / X-Real-IP) | ✅            | ✅                              | — |
| Mesh VPN (Headscale) 統合                    | ✅            | —                               | `docs/MESH-VPN-SPEC.md` |

---

## Java との既知ギャップ

| # | ギャップ                                            | 理由                                                             | トラッカ |
|---|-----------------------------------------------------|------------------------------------------------------------------|---------|
| 1 | Admin HTML ページは stub                            | critical path 外。admin UI 安定後に移植                         | [backlog] P5-6 |
| 2 | 本番相当の SAML 署名 (`xmlsec` 同等)                | Rust 側は simplified 経路。DD-005 により Java sidecar 推奨        | DD-005  |
| 3 | フル Wasm プラグイン runtime                        | 現状はネイティブプラグインで十分。wasmtime 統合は先送り         | [backlog] |

---

## 検証手順

```bash
# Rust
cargo test --workspace

# auth-server unit + integration
cargo test -p volta-auth-server --bins      # 44 unit tests
cargo test -p volta-auth-core --features postgres -- --ignored  # integration

# ルート数サニティチェック (~96 が出るはず)
rg -c '^\s+\.route\(' auth-server/src/app.rs
```

Java 側コミットから Rust 着地点への trace は
[`auth-server/docs/sync-from-java-2026-04-14.md`](../auth-server/docs/sync-from-java-2026-04-14.md)
を参照。
