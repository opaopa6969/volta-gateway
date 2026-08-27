# volta-auth-server

Java volta-auth-proxy の 100% 互換 Rust 置き換え。**Java/JVM 不要。**

## 概要

volta-auth-server は Axum ベースの認証 API サーバーで、auth-core ライブラリの上に 126 の HTTP エンドポイントを公開します。

```
volta-gateway (リバースプロキシ)
  ↓ ForwardAuth: GET /auth/verify
volta-auth-server (認証 API) ← このクレート
  ↓ sqlx
PostgreSQL
```

## 起動

```bash
# 環境変数
export DATABASE_URL=postgres://localhost/volta
export JWT_SECRET=your-secret-key
export KEY_CIPHER_MASTER_KEY=your-independent-encryption-key
export IDP_PROVIDER=google
export IDP_CLIENT_ID=your-google-client-id
export IDP_CLIENT_SECRET=your-google-client-secret

# 起動 (port 7070)
cargo run --release -p volta-auth-server
```

## 環境変数

| 変数 | デフォルト | 説明 |
|------|-----------|------|
| `PORT` | 7070 | HTTP ポート |
| `DATABASE_URL` | postgres://localhost/volta | PostgreSQL 接続 URL |
| `JWT_SECRET` | `volta-dev-secret-change-me-in-prod` | JWT 署名シークレット (HS256)。本番では必ず変更 |
| `KEY_CIPHER_MASTER_KEY` | (`JWT_SECRET` に fallback、WARN を記録) | PKCE verifier・TOTP secret 等の保存データ暗号鍵。本番では JWT 署名鍵と分離する |
| `SESSION_TTL_SECONDS` | 28800 (8h) | セッション有効期間 |
| `COOKIE_DOMAIN` | (空) | Cookie の Domain 属性 |
| `FORCE_SECURE_COOKIE` | false | HTTPS なしでも Secure フラグ |
| `BASE_URL` | http://localhost:7070 | リダイレクト用ベース URL |
| `STATE_SIGNING_KEY` | (JWT_SECRET) | OIDC state パラメータ署名鍵 |
| `IDP_PROVIDER` | google | デフォルト IdP (google/github/microsoft) |
| `IDP_CLIENT_ID` | (空) | OAuth2 Client ID |
| `IDP_CLIENT_SECRET` | (空) | OAuth2 Client Secret |
| `SAML_SKIP_SIGNATURE` | false | SAML 署名検証スキップ (開発用) |
| `OUTBOX_POLL_SECS` | 5 | Webhook 配信 worker ポーリング間隔 |

### 保存データ暗号鍵の分離と移行

本番では `KEY_CIPHER_MASTER_KEY` を必ず設定し、`JWT_SECRET` と用途を分離する。
未設定時は後方互換のため `JWT_SECRET` を暗号鍵として使うが、起動時に WARN を記録する。
この fallback は移行期間専用であり、新規環境の既定運用ではない。

既存環境が fallback を使っている場合は、次の順序なら既存暗号文を失わずに分離できる。

1. 現在の `JWT_SECRET` と**同じ値**を `KEY_CIPHER_MASTER_KEY` に設定し、`JWT_SECRET` は変更せず再起動する。
2. 既存の TOTP 認証と進行中の OIDC フローが復号でき、fallback WARN が消えたことを確認する。
3. `KEY_CIPHER_MASTER_KEY` を維持したまま `JWT_SECRET` だけを新しい値へ rotate する。既存 JWT session は無効になるため、利用者の再ログインを計画する。

`KEY_CIPHER_MASTER_KEY` 自体を変更すると既存暗号文は復号できなくなる。現行実装は
旧鍵との二重読みや一括再暗号化を提供しないため、保存済み secret の再登録・再暗号化計画なしに
この値を rotate してはならない。鍵は secret manager で保管し、十分なランダム値
（例: `openssl rand -hex 32`）を使う。

## エンドポイント一覧 (126 routes)

### 認証
| Method | Path | 説明 |
|--------|------|------|
| GET | /auth/verify | ForwardAuth (gateway 連携) |
| GET | /login | OIDC ログイン開始 |
| GET | /callback | OIDC コールバック |
| POST | /auth/callback/complete | OIDC 完了 (form submit) |
| GET/POST | /auth/logout | ログアウト |
| POST | /auth/refresh | JWT 更新 |
| POST | /auth/switch-tenant | テナント切替 |
| POST | /auth/switch-account | アカウント切替 |
| GET | /select-tenant | テナント選択 |

### SAML
| Method | Path | 説明 |
|--------|------|------|
| GET | /auth/saml/login | SAML IdP リダイレクト |
| POST | /auth/saml/callback | SAML アサーション受信 |

### MFA
| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/users/{id}/mfa/totp/setup | TOTP セットアップ |
| POST | /api/v1/users/{id}/mfa/totp/verify | TOTP 検証 (セットアップ時) |
| DELETE | /api/v1/users/{id}/mfa/totp | TOTP 無効化 |
| GET | /api/v1/users/me/mfa | MFA ステータス |
| POST | /api/v1/users/{id}/mfa/recovery-codes/regenerate | リカバリコード再発行 |
| POST | /auth/mfa/verify | ログイン時 MFA 検証 |

### Magic Link
| Method | Path | 説明 |
|--------|------|------|
| POST | /auth/magic-link/send | マジックリンク送信 |
| GET | /auth/magic-link/verify | マジックリンク検証 |

### Passkey
| Method | Path | 説明 |
|--------|------|------|
| POST | /auth/passkey/start | 認証開始 |
| POST | /auth/passkey/finish | 認証完了 |
| POST | /api/v1/users/{id}/passkeys/register/start | 登録開始 |
| POST | /api/v1/users/{id}/passkeys/register/finish | 登録完了 |
| GET | /api/v1/users/{id}/passkeys | 一覧 |
| DELETE | /api/v1/users/{id}/passkeys/{id} | 削除 |

### User / Session
| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/users/me | プロフィール |
| GET | /api/v1/users/me/tenants | テナント一覧 |
| PATCH | /api/v1/users/{id} | プロフィール更新 |
| DELETE | /api/v1/users/me | アカウント削除 |
| GET | /api/me/sessions | セッション一覧 |
| DELETE | /api/me/sessions/{id} | セッション失効 |
| DELETE | /api/me/sessions | 全セッション失効 |

### Tenant / Member / Invite
| Method | Path | 説明 |
|--------|------|------|
| POST/GET/PATCH | /api/v1/tenants | テナント CRUD |
| POST | /api/v1/tenants/{id}/transfer-ownership | オーナー移譲 |
| GET/PATCH/DELETE | /api/v1/tenants/{id}/members/{id} | メンバー管理 |
| POST/GET/DELETE | /api/v1/tenants/{id}/invitations | 招待管理 |
| POST | /invite/{code}/accept | 招待受諾 |

### IdP / M2M / OAuth
| Method | Path | 説明 |
|--------|------|------|
| GET/POST | /api/v1/tenants/{id}/idp-configs | IdP 設定 |
| GET/POST | /api/v1/tenants/{id}/m2m-clients | M2M クライアント |
| POST | /oauth/token | client_credentials grant |

### Webhook / Billing / Policy
| Method | Path | 説明 |
|--------|------|------|
| CRUD | /api/v1/tenants/{id}/webhooks | Webhook 管理 |
| GET | /api/v1/tenants/{id}/webhooks/{id}/deliveries | 配信ログ |
| GET/POST | /api/v1/tenants/{id}/billing | 課金情報 |
| GET/POST | /api/v1/tenants/{id}/policies | ポリシー管理 |
| POST | /api/v1/tenants/{id}/policies/evaluate | ポリシー評価 |

### GDPR / Device / Audit
| Method | Path | 説明 |
|--------|------|------|
| POST | /api/v1/users/me/data-export | データエクスポート |
| DELETE | /api/v1/users/{id}/data | データ削除 |
| GET/DELETE | /api/v1/users/me/devices | デバイス管理 |
| GET | /api/v1/admin/audit | 監査ログ |

### SCIM 2.0
| Method | Path | 説明 |
|--------|------|------|
| GET/POST | /scim/v2/Users | ユーザー一覧/作成 |
| GET/PUT/PATCH/DELETE | /scim/v2/Users/{id} | ユーザー CRUD |
| GET/POST | /scim/v2/Groups | グループ一覧/作成 |

### Admin
| Method | Path | 説明 |
|--------|------|------|
| GET | /api/v1/admin/{keys,tenants,users,audit} | 管理 API |
| POST | /api/v1/admin/keys/rotate | 鍵ローテーション |
| POST | /api/v1/admin/outbox/flush | Outbox 強制配信 |
| GET | /admin/{tenants,users,members,...} | 管理 HTML ページ |
| GET | /healthz | ヘルスチェック |
| GET | /.well-known/jwks.json | JWKS |

## Cookie 仕様 (Java 互換)

```
__volta_session=<UUID>; Path=/; Max-Age=28800; HttpOnly; SameSite=Lax; Domain=.example.com; Secure
```

## エラーレスポンス (Java 互換)

```json
{
  "error": {
    "code": "SESSION_EXPIRED",
    "message": "セッションの有効期限が切れました。再ログインしてください。"
  }
}
```

## データベース

20 テーブル (auth-core/migrations/ で管理):

users, tenants, memberships, sessions, invitations, invitation_usages,
auth_flows, auth_flow_transitions, user_mfa, mfa_recovery_codes,
magic_links, signing_keys, idp_configs, m2m_clients, user_passkeys,
webhook_subscriptions, outbox_events, webhook_deliveries, audit_logs,
known_devices, trusted_devices, plans, subscriptions, policies

## Local network bypass（既定無効）

`LOCAL_BYPASS_CIDRS` を明示した場合だけ、セッションのない接続元を
network perimeterとして許可します。gatewayからの転送IPを使う場合は、直接接続する
gatewayのCIDRも別途指定してください。

```bash
LOCAL_BYPASS_CIDRS=100.64.0.0/10
LOCAL_BYPASS_TRUSTED_PROXY_CIDRS=10.42.0.0/16
```

`X-Real-IP` / `X-Forwarded-For` は、Axumが取得したpeer IPがtrusted proxyに
一致するときだけ参照されます。公開環境ではbypassを無効のままにすることを推奨します。

## テスト

```bash
cargo test -p volta-auth-server     # SAML テスト (5 tests)
```
