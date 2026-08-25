[English version](getting-started.md)

# volta-gateway Getting Started (日本語)

`git clone` から実際にリクエストが通るところまでを 1 つの端末で完結する手順。
サポートするRust構成を扱う:

1. **Gateway + Rust auth-server** (サポートする本番構成)

`volta-bin` crate は現時点ではコンポーネント／flow の実験的smoke checkであり、
gatewayを起動しないためデプロイ構成には含めない。

## 0. 前提

- Rust 1.75+ (edition 2021)
- PostgreSQL 13+ (auth-core 機能使用時)
- Docker (任意 — 統合テスト用)
- 任意の HTTP バックエンド。無ければ同梱の `mock_backend` を使う

## 1. Clone & build

```bash
git clone https://github.com/opaopa6969/volta-gateway
cd volta-gateway
cargo build --workspace --release
```

ワークスペースは 5 crate (`gateway`, `auth-core`, `auth-server`, `volta-bin`,
`tools/traefik-to-volta`)。編集前に [`docs/architecture-ja.md`](architecture-ja.md)
を一読推奨。

## 2. 最小設定

`my-config.yaml`:

```yaml
server:
  port: 8080

auth:
  volta_url: http://localhost:7070   # Rust auth-server
  timeout_ms: 500                    # fail-closed: 認証側ダウン → 502

routing:
  - host: app.localhost
    backend: http://localhost:3000
    app_id: my-app
```

全項目: [`volta-gateway.full.yaml`](../volta-gateway.full.yaml) 参照。

## 3. mock backend + mock auth で smoke test (DB 不要)

純粋な疎通試験なら PostgreSQL 不要。`gateway` crate に 2 つの example 同梱:

```bash
# Terminal 1 — mock backend on :3000 ({"ok": true} を返す)
cargo run --release -p volta-gateway --example mock_backend

# Terminal 2 — mock auth on :7070 (全リクエスト承認)
cargo run --release -p volta-gateway --example mock_auth

# Terminal 3 — gateway on :8080
cargo run --release -p volta-gateway -- my-config.yaml
```

確認:

```bash
curl -H "Host: app.localhost" http://localhost:8080/api/hi
# => {"ok":true}
```

全レスポンスに `x-request-id` が付き、gateway ログには 5 遷移
(Received → Validated → Routed → AuthChecked → Forwarded → Completed) が
`durationMicros` とともに残る。

## 4. 本物の auth-server (Rust) に切り替え

`auth-server` は正となるRust製の認証サービス。PostgreSQL 必須。
旧実装との対比表は[履歴追跡用](parity-ja.md)としてのみ残す。

```bash
# Postgres 起動
docker run --rm -d --name volta-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
export DATABASE_URL=postgres://postgres:postgres@localhost/postgres
export JWT_SECRET="$(openssl rand -hex 32)"

# auth-server を :7070 で起動 (gateway が見に行く URL と同じ)
cargo run --release -p volta-auth-server

# gateway はそのままでよい (http://localhost:7070 を指す)
cargo run --release -p volta-gateway -- my-config.yaml
```

`http://localhost:8080/login` で OIDC フロー開始。IdP 用の環境変数
(`IDP_PROVIDER`, `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`) は
[`auth-server/README.md`](../auth-server/README.md) に一覧あり。

## 5. 実験用 `volta-bin` scaffold

`volta-bin/` クレート（パッケージ名は `volta`）は、現時点ではauth-coreの
コンポーネントとflow定義がbuildできることを確認する。HTTP gatewayは起動しない。

```bash
cargo run --release -p volta -- my-config.yaml
```

gateway + auth-server の代替デプロイとして使用しないこと。in-process認可は
将来実装であり、サポートするgatewayでのローカルJWT検証は明示的な縮退運転時に
限られる。

## 6. パブリックルート、CORS、ロードバランシング

パブリックルート (webhook、ヘルスチェック):

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    auth_bypass_paths:
      - prefix: /webhooks/
      - prefix: /health
```

CORS は **deny-by-default** (DD-001)。ルート毎に明示的 opt-in:

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    cors_origins:
      - https://app.localhost
```

重み付き canary:

```yaml
routing:
  - host: app.localhost
    backends:
      - url: http://localhost:3000
        weight: 9    # 90%
      - url: http://localhost:3001
        weight: 1    # 10%
```

## 7. HTTPS + Let's Encrypt

TLS-ALPN-01:

```yaml
server:
  port: 8080
  force_https: true

tls:
  domains:
    - app.example.com
  contact_email: admin@example.com
  port: 443
  cache_dir: ./acme-cache
  staging: true   # 本番は false
```

Cloudflare 経由の DNS-01 (ワイルドカード証明書):

```yaml
tls:
  domains:
    - "*.example.com"
  contact_email: admin@example.com
  challenge: dns-01
  dns_provider: cloudflare
  # dns_api_token / dns_zone_id を直接指定することも可能。
  # 実装は CF_DNS_API_TOKEN と CF_ZONE_ID も参照する。
```

## 8. CI での設定検証

```bash
cargo run --release -p volta-gateway -- --validate my-config.yaml
```

不正ルート・未知プラグイン・未定義 backend で非ゼロ終了。デプロイ前に
パイプラインに組み込む。

## 9. ホットリロード

ゼロダウンタイムのルート入替 (`ArcSwap`):

```bash
kill -HUP $(pgrep volta-gateway)
# または
curl -X POST http://localhost:8080/admin/reload
```

## 10. Admin API

全て localhost 限定:

```bash
curl http://localhost:8080/admin/routes     # ルーティングテーブル
curl http://localhost:8080/admin/backends   # backend ヘルス
curl http://localhost:8080/admin/stats      # カウンタ
curl http://localhost:8080/metrics          # Prometheus
```

## 11. 負荷試験

```bash
# 簡易 smoke (hey / wrk)
hey -n 100000 -c 100 -host app.localhost http://localhost:8080/api/hi

# README の数値が出るベンチ
cargo bench -p volta-gateway --bench proxy_bench
```

方法論と Traefik 比 6.6x の出所は [`docs/benchmark-article.md`](benchmark-article.md)。

## 12. 次に読むもの

- [README](../README-ja.md) — 概要とポジショニング
- [`docs/architecture-ja.md`](architecture-ja.md) — FlowEngine / ルーティング / 8 マージルータ / プラグイン
- [`docs/parity-ja.md`](parity-ja.md) — Rust vs Java ルート毎
- [`docs/migration-from-traefik-ja.md`](migration-from-traefik-ja.md) — Traefik 移行ガイド
- [`docs/feedback.md`](feedback.md) — tramli アップグレードループ (3.2 → 3.8)
- [全 YAML リファレンス](../volta-gateway.full.yaml)
