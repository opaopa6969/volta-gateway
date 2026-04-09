[English version](README.md)

# volta-gateway

中小規模 SaaS 向け、ステートマシン駆動の認証対応リバースプロキシ。

**全てのリクエストはレールの上を走る** — ステートマシンが有効な遷移だけを許可する。リクエストスマグリングなし。認証チェック忘れなし。見えない障害なし。

> **大規模 (50+ サービス, Kubernetes, Canary):** [Traefik](https://traefik.io/) + [volta-auth-proxy](https://github.com/opaopa6969/volta-auth-proxy) の ForwardAuth を推奨。Traefik のエコシステムはオーケストレーションで無敵。
>
> **中小規模 SaaS (5-20 サービス, 認証レイテンシ重視):** volta-gateway なら認証チェック 5-10倍速、ステップ別可視化、YAML 1ファイル設定。

## 仕組み

```
Client → Cloudflare (TLS) → volta-gateway (HTTP:8080) → volta-auth-proxy (認証チェック)
                                                       → バックエンド App

リクエストライフサイクル（ステートマシン）:
  RECEIVED → VALIDATED → ROUTED → [認証] → AUTH_CHECKED → [転送] → FORWARDED → COMPLETED
                                            ├── REDIRECT (ログインへ)
                                            ├── DENIED (403)
                                            └── BAD_GATEWAY (volta ダウン)
```

### 状態遷移図

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> Validated : RequestValidator
    Validated --> Routed : RoutingResolver
    Routed --> AuthChecked : [AuthGuard] ← volta /auth/verify
    AuthChecked --> Forwarded : [ForwardGuard] ← backend HTTP
    Forwarded --> Completed : CompletionProcessor

    Received --> BadRequest : ヘッダ過大
    Validated --> BadRequest : 不明なホスト / 不正なパス
    Routed --> Redirect : 401 (未認証)
    Routed --> Denied : 403 (アクセス拒否)
    Routed --> BadGateway : volta ダウン / タイムアウト
    AuthChecked --> BadGateway : バックエンドエラー
    AuthChecked --> GatewayTimeout : バックエンドタイムアウト

    Completed --> [*]
    BadRequest --> [*]
    Redirect --> [*]
    Denied --> [*]
    BadGateway --> [*]
    GatewayTimeout --> [*]
```

この図はエンジンが実行するのと**同じ `FlowDefinition`** から生成される。コード = 図。常に同期。

全ての状態遷移がログに残る。**どこで時間がかかったか**が一目瞭然:

```json
{
  "transitions": [
    {"from": "RECEIVED", "to": "VALIDATED", "duration_us": 5},
    {"from": "VALIDATED", "to": "ROUTED", "duration_us": 2},
    {"from": "ROUTED", "to": "AUTH_CHECKED", "duration_us": 850},
    {"from": "AUTH_CHECKED", "to": "FORWARDED", "duration_us": 12500}
  ],
  "total_us": 13360
}
```

## クイックスタート

```bash
# 1. クローン
git clone https://github.com/opaopa6969/volta-gateway
cd volta-gateway

# 2. 設定（routing を自分のバックエンドに合わせる）
cp volta-gateway.yaml my-config.yaml
# my-config.yaml を編集

# 3. volta-auth-proxy が localhost:7070 で動いていることを確認

# 4. 実行
cargo run -- my-config.yaml
```

## 機能一覧

| 機能 | 詳細 |
|------|------|
| HTTP/1.1 + HTTP/2 | hyper 1.x 自動ネゴシエーション |
| WebSocket tunnel | 双方向 TCP tunnel (1024 接続上限) |
| TLS / Let's Encrypt | rustls-acme, 自動 HTTPS |
| ロードバランシング | ラウンドロビン + 重み付きルーティング (カナリアデプロイ) |
| レート制限 | グローバル + per-IP + per-user (プラグイン) |
| サーキットブレーカー | 5 failures / 30s recovery, idempotent retry, Retry-After |
| 認証キャッシュ | 5秒 TTL cookie ベース — 重複 volta 呼び出しをスキップ |
| 圧縮 | text/json/xml/js を gzip (1MB 閾値) |
| CORS | per-route origins, セキュア・バイ・デフォルト |
| カスタムエラーページ | HTML ディレクトリ + JSON fallback |
| ホットリロード | SIGHUP + HTTP `/admin/reload` — ゼロダウンタイム (ArcSwap) |
| パブリックルート | `public: true` で認証スキップ、`auth_bypass_paths` で webhook 対応 |
| パス書き換え | `strip_prefix`, `add_prefix` で API バージョニング |
| ヘッダー操作 | ルートごとにリクエスト/レスポンスヘッダーを追加・削除 |
| トラフィックミラーリング | シャドウ backend (fire-and-forget, sample_rate) |
| 地理アクセス制御 | `geo_allowlist` / `geo_denylist` (CF-IPCountry) |
| ルート別タイムアウト | `timeout_secs` — LLM backend 120秒、高速 API 5秒 |
| Traceparent | W3C Trace Context 伝搬 (OpenTelemetry 互換) |
| レスポンスキャッシュ | ルート別 LRU + TTL (X-Volta-Cache: HIT/MISS) |
| プラグインシステム | Native Rust プラグイン (api-key-auth, rate-limit-by-user) |
| Config Sources | YAML + services.json + Docker labels + HTTP polling |
| Backend ヘルスチェック | dead backend 自動検出・LB スキップ |
| mTLS backend | 内部 zero-trust 用 mutual TLS |
| バックプレッシャー | グローバル最大同時リクエスト数 (Semaphore) |
| Admin API | /admin/routes, /admin/backends, /admin/stats, /admin/reload, /admin/drain |
| Config 検証 | `volta-gateway --validate config.yaml` (CI/CD 用) |
| L4 proxy | TCP/UDP ポートフォワーディング |
| メトリクス | Prometheus /metrics + レイテンシヒストグラム (8 bucket) |
| Trusted proxies | CF-Connecting-IP / X-Real-IP で real client IP |

## 設定

最小構成 (`volta-gateway.minimal.yaml` 参照):

```yaml
server:
  port: 8080

auth:
  volta_url: http://localhost:7070   # volta-auth-proxy
  timeout_ms: 500                    # フェイルクローズド: volta ダウン → 502

routing:
  - host: app.example.com
    backend: http://localhost:3000
    app_id: app-wiki
    cors_origins:                    # 明示的 CORS (省略 = CORS ヘッダなし)
      - https://app.example.com

  - host: "*.example.com"           # ワイルドカード対応
    backends:                        # ラウンドロビン LB
      - http://localhost:3000
      - http://localhost:3001
```

全フィールドリファレンス: `volta-gateway.full.yaml`

## セキュリティ

| レイヤー | 防御対象 |
|---------|---------|
| **hyper** (HTTP パーサー) | リクエストスマグリング、ヘッダインジェクション、HTTP/2 違反 |
| **SM VALIDATED state** | Host ヘッダ汚染、パストラバーサル、過大リクエスト |
| **認証チェック** | 未認証アクセス（フェイルクローズド: volta ダウン → 502） |
| **レスポンス strip** | バックエンドの X-Volta-* ヘッダ偽装（レスポンスから除去） |

## アーキテクチャ

```
┌────────────────────────────────────────────┐
│  tower::ServiceBuilder                     │
│    TraceLayer → RateLimitLayer → Timeout   │
├────────────────────────────────────────────┤
│  ProxyService (SM ライフサイクル)             │
│                                            │
│  同期判断:              非同期 I/O:          │
│    RECEIVED → VALIDATED    (なし)           │
│    VALIDATED → ROUTED      (なし)           │
│    ROUTED → [External]     volta HTTP 呼出  │
│    AUTH_CHECKED → [Ext]    backend 転送     │
│    FORWARDED → COMPLETED   (なし)           │
│                                            │
│  SM は同期 (~2μs)。I/O は非同期 (hyper)。    │
│  関心の分離。                                │
├────────────────────────────────────────────┤
│  hyper (HTTP) + tokio (非同期ランタイム)      │
└────────────────────────────────────────────┘
```

SM パターンは [tramli](https://github.com/opaopa6969/tramli) から — 不正な遷移が構造的に存在できない制約付きフローエンジン。

## なぜ Docker labels ではなく 1 YAML なのか？

Traefik ユーザーが最初に聞く質問。

**Labels が輝くとき:** 各チームが独立してサービスをデプロイする大規模組織。docker-compose に 3 行追加で OK。

**Labels が辛くなるとき:**
- middleware chain が 20 行超え → 可読性ゼロ
- 全ルートが docker-compose 10 ファイルに散在 → 一覧が見えない
- labels の typo でルーティングが壊れても気づきにくい（検証なし）
- ForwardAuth + CORS + rate limit + path rewrite を全部 labels で書く地獄

**volta-gateway の選択:** 1 YAML ファイル、起動時に検証。全ルート・ミドルウェア・バックエンドが一箇所に。不正な config は起動時に即エラー。

Docker label 検出が必要なチームは [Config Sources](#config-sources) で services.json / Docker labels / HTTP polling + ライブリロードに対応。

## vs Traefik (実測済み)

同条件ベンチマーク: localhost mock auth + mock backend。Traefik v3.4 (Docker) + ForwardAuth vs volta-gateway (native release)。[詳細結果](benches/e2e_results.md)

| 指標 | volta-gateway | Traefik + ForwardAuth | |
|------|--------------|----------------------|---|
| **p50 レイテンシ** | **0.252 ms** | **1.673 ms** | **6.6倍高速** |
| 平均レイテンシ | 0.395 ms | 1.777 ms | 4.5倍高速 |
| p99 レイテンシ | 1.235 ms | 2.373 ms | 1.9倍高速 |
| SM オーバーヘッド | 1.69 μs | — | 全体の約1% |

| | volta-gateway | Traefik |
|---|---|---|
| 認証モデル | localhost HTTP (コネクションプール) | ForwardAuth ミドルウェア (2ホップ) |
| リクエスト可視性 | ステップ別 SM 遷移 + μs タイミング | 「入って出た」だけ |
| 設定 | 1 YAML ファイル | Docker labels + traefik.yml + middleware chain |
| ルーティング | Host → backend (ワイルドカード, ラウンドロビン) | Labels, file, Consul, etcd, ... |
| CORS | per-route, セキュア・バイ・デフォルト (DD-001) | ミドルウェアチェーン |
| デバッグ | SM state ログで障害点が一目瞭然 | Traefik デバッグログを読む |

## tramli での開発

volta-gateway は [tramli](https://github.com/opaopa6969/tramli)（[crates.io](https://crates.io/crates/tramli) で `tramli = "0.1"`）をステートマシンエンジンとして使用。

### なぜ tramli か？

プロキシのリクエストライフサイクルが **Rust 8行** で定義される:

```rust
Builder::new("proxy")
    .from(Received).auto(Validated, RequestValidator { routing })
    .from(Validated).auto(Routed, RoutingResolver { routing })
    .from(Routed).external(AuthChecked, AuthGuard)
    .from(AuthChecked).external(Forwarded, ForwardGuard)
    .from(Forwarded).auto(Completed, CompletionProcessor)
    .on_any_error(BadGateway)
    .build()  // ← ここで8項目検証
```

`build()` が起動時に検証: 到達可能性、DAG、requires/produces チェーン等。**`build()` が通れば、フローは構造的に正しい。**

### B 方式: sync SM + async I/O

tramli は意図的に同期（リクエストあたり ~2μs）。非同期 I/O はエンジンの外:

```rust
// 1. 同期: SM 判断 (~1μs)
let flow_id = engine.start_flow(&def, &id, initial_data)?;
// 自動連鎖: RECEIVED → VALIDATED → ROUTED（External で停止）

// 2. 非同期: volta 認証チェック (~500μs)
let auth = volta_client.check_auth(&req).await;

// 3. 同期: SM 判断 (~300ns)
engine.resume_and_execute(&flow_id, auth_data)?;

// 4. 非同期: バックエンド転送 (~1-50ms)
let resp = backend.forward(&req).await;

// 5. 同期: SM 判断 (~300ns)
engine.resume_and_execute(&flow_id, resp_data)?;
// FORWARDED → COMPLETED（ターミナル）
```

SM はブロックしない。I/O は SM に入らない。きれいな分離。

### Processor の追加方法

1. `StateProcessor<ProxyState>` を実装する struct を定義
2. `requires()`（入力型）と `produces()`（出力型）を宣言
3. Builder に `.from(X).auto(Y, MyProcessor)` を追加
4. `build()` がチェーン全体を検証 — コンパイルが通り `build()` が通れば動く

詳細は [tramli ドキュメント](https://github.com/opaopa6969/tramli)。このプロキシを作った実体験は[ユーザーレビュー](https://github.com/opaopa6969/tramli/blob/main/docs/review-volta-gateway-ja.md)を参照。

## ワークスペース構成

```
volta-gateway/
  Cargo.toml              ワークスペースルート
  gateway/                HTTP リバースプロキシ (30+ 機能)
  auth-core/              認証ライブラリ — JWT, セッション, OIDC/MFA/Passkey フロー
  volta-bin/              統合バイナリ (gateway + auth in-process)
  tools/traefik-to-volta/ 設定変換 CLI
```

### auth-core

in-process 認証ライブラリ。auth-proxy への HTTP ラウンドトリップ不要。

| モジュール | 用途 |
|-----------|------|
| `jwt` | JWT 検証 + 発行 (HS256, RSA) |
| `session` | Cookie → JWT 検証 → X-Volta-* ヘッダー |
| `store` | DAO trait (User, Tenant, Membership, Invitation, Session, Flow) |
| `store::pg` | PostgreSQL 実装 (sqlx, `postgres` feature) |
| `policy` | RBAC ポリシーエンジン |
| `flow` | tramli SM フロー (OIDC, MFA, Passkey, Invite) |
| `service` | async オーケストレーター (IdP/Store/JWT で SM を駆動) |
| `idp` | OAuth2/OIDC クライアント (Google, GitHub, Microsoft, LinkedIn, Apple) |
| `totp` | MFA 用 TOTP 検証 |
| `passkey` | WebAuthn/Passkey サービス (webauthn-rs, `webauthn` feature) |

```bash
# PostgreSQL サポート付きビルド
cargo build -p volta-auth-core --features postgres

# テスト (ユニット)
cargo test -p volta-auth-core

# インテグレーションテスト (Docker 必要)
cargo test -p volta-auth-core --features postgres -- --ignored
```

## 要件

- Rust 1.75+ (edition 2021)
- PostgreSQL 13+ (auth-core `postgres` feature 使用時)
- Docker (インテグレーションテスト用)
- バックエンド App が動作中

## ライセンス

MIT
