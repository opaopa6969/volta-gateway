[English version](architecture.md)

# volta-gateway アーキテクチャ

> [README](../README-ja.md) の補足文書。ここでは「各パーツがどう噛み合うか」を記す。
> 中心には tramli FlowEngine、その周りにルーティング、auth-server の 5 マージ構成、
> プラグインシステム、レートリミッタ多層が並ぶ。

## 1. ワークスペース構成

```
volta-gateway/                       Cargo ワークスペースルート
├── gateway/          HTTP リバースプロキシ (auth-server の 96 ルートを前段で捌く)
├── auth-core/        認証ライブラリ — JWT/セッション/OIDC・MFA・Passkey SM フロー
├── auth-server/      Axum HTTP API — Java volta-auth-proxy の 1:1 置き換え
├── volta-bin/        統合バイナリ (gateway + auth-core in-process)
└── tools/
    └── traefik-to-volta/  Traefik → volta 設定変換 CLI
```

共通依存: `tramli = "3.8"` と `tramli-plugins = "3.6.1"` を gateway・auth-core 双方で
固定。この pin は装飾ではない ([§4](#4-tramli-バージョンポリシー) 参照)。

## 2. エッジの FlowEngine

gateway に入った**全リクエスト**は **1 個の tramli `FlowInstance`** を駆動する。
定義は `gateway/src/flow.rs`:

```text
         ┌─────────┐   ┌───────────┐   ┌────────┐
[*] ──▶ │Received │──▶│ Validated │──▶│ Routed │──▶ [AuthGuard] ──▶ AuthChecked
         └─────────┘   └───────────┘   └────────┘        │
              │              │             │              ▼
              └── BAD_REQUEST, REDIRECT, DENIED, BAD_GATEWAY, GATEWAY_TIMEOUT
                                                          │
                                                          ▼
                                                   [ForwardGuard] ──▶ Forwarded
                                                                         │
                                                                         ▼
                                                                     Completed [*]
```

Processor (同期、各 <2µs):

| Processor             | `requires`        | `produces`      | 役割                                                            |
|-----------------------|-------------------|-----------------|-----------------------------------------------------------------|
| `RequestValidator`    | `RequestData`     | —               | header/body サイズ・host・パストラバーサル (literal + URL-encoded) チェック |
| `RoutingResolver`     | `RequestData`     | `RouteTarget`   | host → backend 解決、ワイルドカード + ラウンドロビン + 重み付き LB  |
| `CompletionProcessor` | `BackendResponse` | —               | メトリクス確定、遷移ログ吐き出し                                |

Guard (同期判断、非同期 I/O はエンジン外):

| Guard          | 対応する External 遷移    | 外部入力                                                 |
|----------------|---------------------------|----------------------------------------------------------|
| `AuthGuard`    | Routed → AuthChecked      | `AuthData` (volta の非同期チェック後に注入)              |
| `ForwardGuard` | AuthChecked → Forwarded   | `BackendResponse` (バックエンド呼び出し後に注入)         |

### B 方式: sync SM + async I/O

```rust
let flow_id = engine.start_flow(&def, &id, initial_data)?; // 同期 ~1µs (auto chain)
let auth    = volta_client.check_auth(&req).await;          // 非同期、SM の外
engine.resume_and_execute(&flow_id, auth_data)?;            // 同期 ~300ns
let resp    = backend.forward(&req).await;                  // 非同期、SM の外
engine.resume_and_execute(&flow_id, resp_data)?;            // 同期 ~300ns、終端へ
```

`build()` は起動時に 8 項目 (到達性・DAG・External は状態あたり最大 1・requires/produces
チェーン等) を検証する。`build()` が通れば構造的に正しい。詳細は
[tramli 側レビュー](https://github.com/opaopa6969/tramli/blob/main/docs/review-volta-gateway-ja.md)。

## 3. ルーティング

`gateway/src/proxy.rs` (約 1.3k LoC) が `RoutingTable` を持つ。これは host を key とした
map (exact + wildcard) を `ArcSwap` で包んだもの。各 `RouteTarget` の中身:

- `backend` / `backends` (ラウンドロビン / 重み付き)
- optional `path_prefix` (例: `/saml/*` を Java sidecar に転送 — DD-005)
- `public`, `auth_bypass_paths`, `cors_origins`, `timeout_secs`
- `geo_allowlist` / `geo_denylist` (CF-IPCountry)
- `strip_prefix` / `add_prefix`、ヘッダ add/remove ルール
- `mirror` シャドウ backend (fire-and-forget, `sample_rate`)
- `plugins: Vec<PluginConfig>` ([§5](#5-プラグインシステム))

Config source (YAML + services.json + Docker labels + HTTP polling) は
`ConfigMerger` で 1 つの `RoutingTable` にまとめられ、`SIGHUP` または
`POST /admin/reload` で `ArcSwap` によりホットスワップされる。

## 4. tramli バージョンポリシー

`tramli = "3.8"` をワークスペース全体で固定するのは以下の理由:

1. gateway のリクエスト FlowEngine と auth-core の OIDC/MFA/Passkey/Invite フローは
   `FlowContext` 型を共有する。drift があるとコンパイルが通らない。
2. マイナーアップ (3.2 → 3.8) の各段は本番で遭遇した摩擦を 1 つずつ削っている。
   往復経緯は [`docs/feedback.md`](feedback.md) 参照。
3. `tramli-plugins = 3.6.1` の `NoopTelemetrySink` はベンチマーク基線で必須
   (`docs/benchmark-article.md` 参照)。

## 5. auth-server: 5 マージルータ

`auth-server/src/app.rs` では **96 本の Axum ルート**をマウントする。ルータは意図的に
**コアルータ + 5 本のレート制限付き `route_layer` サブルータ**という形で合成される:

```rust
Router::new()
    // レート制限なしの ~80 ルート (auth / session / MFA setup / admin / SCIM / …)
    …
    .merge(oidc_routes)     // rl_oidc    10/min/IP
    .merge(mfa_routes)      // rl_mfa      5/min/IP
    .merge(passkey_routes)  // rl_passkey  5/min/IP
    .merge(invite_routes)   // rl_invite  20/min/IP
    .merge(magic_routes)    // rl_magic    5/min/IP
    .with_state(state)
```

**なぜこの形か?** Axum の `route_layer` はサブルータ**内部**のルートにしか適用されない。
ブルートフォース対象の敏感なエンドポイントだけを個別サブルータに置いて `RateLimiter` を
付与すれば、他の ~80 ルートに余計なミドルウェアコストを払わずに済む。Java 側の
per-endpoint `@RateLimit(limit=N, window=60s)` と 1:1 対応する。

各リミッタは `RateLimiter::new("oidc", 10, Duration::from_secs(60))` インスタンスで、
`limit_by_ip` ミドルウェアによりクライアント IP を key とする。

ルート分類 (全表は [`parity.md`](parity-ja.md) 参照):

| カテゴリ                                | 数   | 例 |
|-----------------------------------------|------|----|
| Auth (verify/logout/refresh/switch)     | 6    | `/auth/verify`, `/auth/refresh` |
| OIDC                                    | 3    | `/login`, `/callback`, `/auth/callback/complete` |
| SAML                                    | 2    | `/auth/saml/login`, `/auth/saml/callback` |
| MFA (TOTP + challenge)                  | 6    | `/mfa/challenge`, `/auth/mfa/verify` |
| Magic Link                              | 2    | `/auth/magic-link/send`, `/auth/magic-link/verify` |
| Passkey                                 | 6    | `/auth/passkey/*`, `/api/v1/users/{id}/passkeys/*` |
| Session (user + admin)                  | 7    | `/api/me/sessions`, `/admin/sessions` |
| User profile                            | 2    | `/api/v1/users/me`, `/api/v1/users/me/tenants` |
| Tenant / Member / Invite                | 11   | `/api/v1/tenants/{id}`, `/invite/{code}/accept` |
| IdP / M2M / OAuth token                 | 5    | `/api/v1/tenants/{id}/idp-configs`, `/oauth/token` |
| Webhook                                 | 6    | `/api/v1/tenants/{id}/webhooks[/id[/deliveries]]` |
| Admin API + HTML stub                   | 14   | `/api/v1/admin/*`, `/admin/*` |
| Billing / Policy / GDPR                 | 7    | `/api/v1/tenants/{id}/billing`, `/api/v1/users/me/data-export` |
| SCIM 2.0                                | 8    | `/scim/v2/Users`, `/scim/v2/Groups` |
| Signing keys                            | 3    | `/api/v1/admin/keys[/rotate|/{kid}/revoke]` |
| Viz + SSE                               | 3    | `/viz/flows`, `/viz/auth/stream`, `/api/v1/admin/flows/{id}/transitions` |
| Health + JWKS                           | 2    | `/healthz`, `/.well-known/jwks.json` |
| **合計**                                | **~96** | |

## 6. auth-core フローライブラリ

`auth-core/src/flow/` には Java `volta-auth-proxy` から 1:1 ポートした 4 つの tramli
`FlowDefinition` がある:

| ファイル            | 用途 |
|---------------------|------|
| `flow/oidc.rs`      | OIDC ログイン (INIT → REDIRECTED → CALLBACK → TOKEN → DONE) |
| `flow/mfa.rs`       | MFA TOTP チャレンジ (PENDING → VERIFIED / FAILED) |
| `flow/passkey.rs`   | WebAuthn 登録 + 認証 (2 経路) |
| `flow/invite.rs`    | テナント招待受諾 |
| `flow/mermaid.rs`   | 上記 4 フローの Mermaid 出力 |
| `flow/validate.rs`  | フロー定義検証ヘルパ |

これらは `auth-core::AuthService` という非同期オーケストレータから駆動される。
永続化は `auth_flows` + `auth_flow_transitions` テーブルへの `FlowPersistence` が
担当 (楽観ロック付き)。

DD-011 に従い、auth-core の tramli は**長命な認証状態** (ログイン試行・チャレンジ・
招待ライフサイクル) を管理する。HTTP リクエスト毎の状態機械は `gateway/src/flow.rs`
の方だけに置く。

## 7. プラグインシステム

`gateway/src/plugin.rs` (約 420 LoC) は **tramli 風プラグインライフサイクル**を実装:

```text
LOADED ──▶ VALIDATED ──▶ ACTIVE ◀──▶ ERROR
                  │
                  └──▶ REJECTED  (検証失敗)
```

### Phase 1: ビルトインネイティブプラグイン

| プラグイン          | 役割 |
|---------------------|------|
| `ApiKeyAuth`        | public ルート向け header/query/cookie ベース API キー検証 |
| `RateLimitByUser`   | `X-Volta-User-Id` (auth-server 由来) を key にしたユーザ別レート制限 |
| `Monetizer`         | 課金ヘッダ注入 (`X-Monetizer-Plan`, `-Status`, `-Features`, `-Show-Ads`, `-Trial-End`)。TTL キャッシュ + LRU safety valve (DD-016) |
| `HeaderInjector`    | 静的ヘッダ add/remove |

YAML 例:

```yaml
routing:
  - host: api.example.com
    backend: http://localhost:3000
    plugins:
      - name: rate-limit-by-user
        config:
          limit: "60"
          window_secs: "60"
      - name: monetizer
        config:
          billing_url: "http://localhost:7080/billing"
          cache_ttl_secs: "30"
          cache_max_entries: "10000"
```

### Phase 2 (予定): Wasm サンドボックスプラグイン

`plugin_type: wasm` は `PluginConfig` で予約済。`path:` に `.wasm` を指定する設計。
実装 (wasmtime) は backlog。

## 8. レートリミッタ — 3 層

1. **gateway グローバル** (`gateway/src/...`): `tower::limit::RateLimitLayer` +
   `Semaphore` によるバックプレッシャ。接続洪水からプロセスを守る。
2. **gateway ルート別 / ユーザ別**: `RateLimitByUser` プラグイン (プラグインスコープ)。
3. **auth-server エンドポイント別**: `auth-server/src/app.rs` の **5 個の
   `route_layer`** リミッタ (OIDC / MFA / Passkey / Invite / Magic Link)。

つまり `/login` 宛のリクエストは (1) + (3) を通過し、monetized なルートの `/api/...`
は (1) + (2) を通過する。

## 9. セキュリティ姿勢

| レイヤー                          | 防御対象                                                    |
|-----------------------------------|-------------------------------------------------------------|
| `hyper` HTTP パーサ               | request smuggling、header injection、HTTP/2 フレーム濫用    |
| `ProxyState::Validated`           | Host ヘッダ汚染、パストラバーサル (literal + URL-encoded)   |
| AuthGuard                         | 未認証アクセス、volta-auth-server ダウン時は fail-closed    |
| `auth_public_url` suffix match    | OIDC コールバックのオープンリダイレクト (`ad2a0a1`)         |
| レスポンスヘッダ strip            | バックエンドからの `X-Volta-*` 偽装                          |
| レートリミッタ (§8)               | OIDC / MFA ブルートフォース、招待スパム                     |
| `subtle::ConstantTimeEq`          | HMAC / クライアントシークレット比較のタイミング攻撃         |
| `security::reject_xml_doctype`    | SAML アサーション中の XXE                                   |
| `security::normalize_email` (NFC) | 招待・サインアップでの Unicode ホモグリフ                   |
| `KeyCipher` (AES-GCM + PBKDF2)    | PKCE verifier の at-rest 露出                               |

Java upstream `abca91e` (#1–#21) の 20 件中 18 件を Rust にポート、残り 3 件も
`KeyCipher` 導入で 0.3.0 時点で閉じている。詳細は
`auth-server/docs/sync-from-java-2026-04-14.md`。

## 10. 可観測性

- 全遷移に `durationMicros` 付与 (tramli 3.3+)。
- Prometheus `/metrics` — レイテンシヒストグラム (8 bucket)。
- `/admin/routes`, `/admin/backends`, `/admin/stats` — 運用 introspection
  (localhost 限定)。
- `/viz/auth/stream` — Redis pub/sub 経由の SSE auth event fan-out。
- `/viz/flows` + `/api/v1/admin/flows/{id}/transitions` — tramli-viz 連携フック。

## 11. 参照

- [README](../README-ja.md) / [英語版](../README.md)
- [Parity (Java 対比)](parity-ja.md) / [英語版](parity.md)
- [Getting started](getting-started-ja.md) / [英語版](getting-started.md)
- [tramli feedback ループ](feedback.md)
- [HANDOFF — セッション記録](HANDOFF.md)
- [backlog](backlog.md)
- [benchmark-article](benchmark-article.md)
- [migration-from-traefik](migration-from-traefik-ja.md)
- 設計決定: [DD-001 CORS default-deny](../dge/decisions/DD-001-cors-default-deny.md) ·
  [DD-002 L4 proxy scope](../dge/decisions/DD-002-l4-proxy-scope.md) ·
  [DD-005 Java→Rust 移行](../dge/decisions/DD-005-java-to-rust-migration.md) ·
  [DD-006 Workspace](../dge/decisions/DD-006-auth-proxy-rs-repo.md)
