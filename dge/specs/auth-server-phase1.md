# auth-server Phase 1 — HTTP API 基盤

> Status: Spec
> Date: 2026-04-09
> Goal: gateway が Java auth-proxy の代わりに Rust auth-server を使えるようにする

## 概要

`auth-server/` crate を新設。Axum で HTTP API を公開し、
auth-core の AuthService / Store を HTTP エンドポイントとして expose。

## crate 構成

```
volta-gateway/
  auth-server/          ← NEW
    Cargo.toml
    src/
      main.rs           HTTP サーバー起動
      app.rs            Axum Router 構築
      handlers/
        auth.rs         /auth/verify, /auth/logout, /auth/refresh
        oidc.rs         /login, /callback, /auth/callback/complete
        session.rs      /api/me/sessions
        user.rs         /api/v1/users/me
        health.rs       /healthz, /.well-known/jwks.json
      middleware/
        auth_check.rs   セッション検証ミドルウェア
        csrf.rs         CSRF 保護
      state.rs          AppState (stores + services)
      error.rs          ApiError → HTTP response
```

## 依存

```toml
[dependencies]
volta-auth-core = { path = "../auth-core", features = ["postgres"] }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["trace", "cors"] }
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "postgres"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
uuid = { version = "1", features = ["v4"] }
```

## AppState

```rust
#[derive(Clone)]
pub struct AppState {
    pub db: PgStore,
    pub auth_service: Arc<AuthService>,
    pub jwt_verifier: JwtVerifier,
    pub jwt_issuer: JwtIssuer,
}
```

## エンドポイント仕様

### P1-2: GET /auth/verify

gateway の ForwardAuth が呼ぶ。Cookie からセッション検証し、X-Volta-* ヘッダーを返す。

```
Request:  Cookie: volta_session=<JWT>
Response: 200 + X-Volta-User-Id, X-Volta-Tenant-Id, X-Volta-Roles, ...
          401 if no/invalid session
```

**実装:** auth-core の `SessionVerifier::verify()` を呼ぶ。

### P1-3: GET /login

OIDC プロバイダーへリダイレクト。

```
Request:  GET /login?provider=google&redirect_uri=https://app/callback
Response: 302 → https://accounts.google.com/o/oauth2/...
```

**実装:** `AuthService::oidc_start()` → redirect URL を返す。

### P1-3: GET /callback

OIDC プロバイダーからのコールバック。

```
Request:  GET /callback?code=xxx&state=yyy
Response: Set-Cookie: volta_session=<JWT>; 302 → return_to URL
```

**実装:** `AuthService::oidc_callback()` → JWT 発行 → Cookie 設定。

### P1-4: POST /auth/logout

セッション無効化。

```
Request:  Cookie: volta_session=<JWT>
Response: 200; Set-Cookie: volta_session=; (clear)
```

**実装:** セッション ID 抽出 → `SessionStore::revoke()`

### P1-5: POST /auth/refresh

JWT 更新。

```
Request:  Cookie: volta_session=<JWT>; Body: { refresh_token: "..." }
Response: 200; { jwt: "...", refresh_token: "...", expires_at: ... }
```

**実装:** `AuthService::token_refresh()`

### P1-6: GET /api/me/sessions

ユーザーのアクティブセッション一覧。

```
Response: [{ session_id, ip_address, user_agent, created_at, last_active_at }]
```

### P1-7: GET /api/v1/users/me

認証ユーザーのプロフィール。

```
Response: { id, email, display_name, tenants: [{ id, name, slug, role }] }
```

### P1-8: GET /.well-known/jwks.json

JWT 公開鍵 (RS256 の場合)。HS256 の場合は空。

### P1-10: sessions テーブル

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    return_to VARCHAR(2048),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    invalidated_at TIMESTAMPTZ,
    mfa_verified_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    csrf_token VARCHAR(128)
);
```

## 認証ミドルウェア

```rust
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let session = extract_session_from_cookie(&req, &state.jwt_verifier);
    match session {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "unauthorized").into_response(),
    }
}
```

## 設定

```yaml
auth_server:
  port: 7070              # auth API ポート
  database_url: postgres://localhost/volta
  jwt_secret: "..."       # or jwt_rsa_private_key_path
  jwt_ttl_secs: 3600
  cookie_name: volta_session
  cookie_domain: .example.com
  idp:
    provider: google
    client_id: "..."
    client_secret: "..."
```

## テスト

- Unit: handler 単体テスト (mock store)
- Integration: axum::test::TestClient + testcontainers PostgreSQL
- E2E: auth-server 起動 → gateway → OIDC callback → セッション確認

## 完了条件

`volta-gateway --auth-mode=rust` で:
1. `/login` → Google OIDC redirect
2. `/callback` → JWT 発行 → Cookie 設定
3. gateway `/auth/verify` → 200 + X-Volta-* headers
4. `/auth/logout` → セッション無効化
