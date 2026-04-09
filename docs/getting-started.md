# Getting Started with volta-gateway

volta-gateway は認証対応リバースプロキシ。ステートマシンでリクエストライフサイクルを制御し、
Traefik + ForwardAuth 比 **6.6x 高速** な認証チェックを提供します。

## 前提条件

- Rust 1.75+
- バックエンドアプリ (任意の HTTP サーバー)

## 1. インストール

```bash
git clone https://github.com/opaopa6969/volta-gateway
cd volta-gateway
cargo build --release
```

## 2. 最小設定

`my-config.yaml` を作成:

```yaml
server:
  port: 8080

auth:
  volta_url: http://localhost:7070   # 認証サーバー
  timeout_ms: 500

routing:
  - host: app.localhost
    backend: http://localhost:3000   # バックエンドアプリ
    app_id: my-app
```

## 3. バックエンドを起動

お手持ちのアプリを port 3000 で起動するか、テスト用 mock を使用:

```bash
# テスト用 mock backend
cargo run --release --example mock_backend &

# テスト用 mock auth (全リクエスト承認)
cargo run --release --example mock_auth &
```

## 4. volta-gateway を起動

```bash
cargo run --release -p volta-gateway -- my-config.yaml
```

```
INFO volta-gateway starting port=8080
INFO listening addr=0.0.0.0:8080
```

## 5. リクエスト送信

```bash
curl -H "Host: app.localhost" http://localhost:8080/api/test
```

レスポンスにバックエンドの応答が返ります。
`x-request-id` ヘッダーで各リクエストを追跡できます。

## 認証なしの Public ルート

webhook エンドポイントなど、認証をスキップしたいルートは `public: true`:

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    public: true                    # 認証チェックなし
```

特定パスだけ認証をバイパス:

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    auth_bypass_paths:
      - prefix: /webhooks/          # /webhooks/* は認証なし
      - prefix: /health
```

## CORS 設定

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    cors_origins:
      - https://app.localhost       # 許可するオリジン
      # - "*"                       # ワイルドカード (非推奨)
```

`cors_origins` を省略 = CORS ヘッダーなし (安全なデフォルト)。

## HTTPS / Let's Encrypt

```yaml
server:
  port: 8080
  force_https: true                 # HTTP → HTTPS リダイレクト

tls:
  domains:
    - app.example.com
  contact_email: admin@example.com
  port: 443
  cache_dir: ./acme-cache
  staging: true                     # テスト時は true (本番は false)
```

## ロードバランシング

```yaml
routing:
  - host: app.localhost
    backends:
      - url: http://localhost:3000
        weight: 3                   # 75% のトラフィック
      - url: http://localhost:3001
        weight: 1                   # 25% のトラフィック
```

## 設定検証

CI/CD で設定ファイルの事前検証:

```bash
cargo run --release -p volta-gateway -- --validate my-config.yaml
```

無効な設定はエラーメッセージとともに非ゼロで終了します。

## ホットリロード

設定変更をゼロダウンタイムで反映:

```bash
# SIGHUP シグナルで再読み込み
kill -HUP $(pgrep volta-gateway)

# または Admin API 経由
curl -X POST http://localhost:8080/admin/reload
```

## Admin API

localhost からのみアクセス可能:

```bash
# ルーティング一覧
curl http://localhost:8080/admin/routes

# バックエンド健全性
curl http://localhost:8080/admin/backends

# 統計情報
curl http://localhost:8080/admin/stats

# Prometheus メトリクス
curl http://localhost:8080/metrics
```

## In-Process 認証 (auth-core)

volta-auth-proxy への HTTP ラウンドトリップを排除し、
JWT 検証を in-process で行うことで認証レイテンシを **250μs → 1μs** に削減:

```bash
# 統合バイナリ (gateway + auth-core)
cargo run --release -p volta-bin -- my-config.yaml
```

auth-core の設定例:

```yaml
auth:
  jwt_secret: "your-secret-key"     # in-process JWT 検証
  cookie_name: volta_session        # セッション Cookie 名
```

## Docker Compose 例

```yaml
services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/etc/volta/config.yaml
    command: ["/usr/local/bin/volta-gateway", "/etc/volta/config.yaml"]

  backend:
    image: your-app:latest
    labels:
      volta.host: app.localhost
      volta.port: "3000"
      volta.app_id: my-app
```

## 次のステップ

- [Full config reference](../volta-gateway.full.yaml) — 全設定項目
- [Benchmark results](benchmark-article.md) — パフォーマンス詳解
- [Migration from Traefik](migration-from-traefik.md) — Traefik からの移行ガイド
