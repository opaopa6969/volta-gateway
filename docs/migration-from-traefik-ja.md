[English version](migration-from-traefik.md)

# 移行ガイド: Traefik → volta-gateway

## 概要

volta-gateway は volta-auth-proxy のリバースプロキシとして Traefik を置き換える。このガイドでは Traefik の概念を volta-gateway にマッピングする。

## 構成の変更

```
変更前:
  Client → CF → Traefik → volta (ForwardAuth) → App

変更後:
  Client → CF → volta-gateway → volta (localhost /auth/verify) → App
```

Traefik の ForwardAuth (2 HTTP 往復, 4-10ms) → volta-gateway の内蔵 auth (1 localhost 呼出, 0.5-1ms)。

## 概念マッピング

| Traefik | volta-gateway | 備考 |
|---------|---------------|------|
| `traefik.yml` | `volta-gateway.yaml` | 1ファイルで完結 |
| Docker labels | `routing:` セクション | Docker 不要 |
| ミドルウェアチェーン | SM Processor | 構造的、設定チェーンではない |
| ForwardAuth | 内蔵 auth (localhost) | 追加 HTTP ホップなし |
| `entryPoints` | `server.port` | 1ポート |
| Let's Encrypt (ACME) | Cloudflare (TLS 終端) | CF が証明書を管理 |
| Dashboard (`/api/`) | `/metrics` + `/healthz` | Prometheus 互換 |
| Rate limiting ミドルウェア | 内蔵 per-IP rate limiter | YAML で設定 |
| IP ホワイトリスト | `ip_allowlist` (ルートごと) | CIDR 対応 |

## 設定の変換

### Traefik Docker Labels → volta-gateway.yaml

```yaml
# Traefik
traefik.http.routers.wiki.rule=Host(`wiki.example.com`)
traefik.http.services.wiki.loadbalancer.server.port=3000

# volta-gateway
routing:
  - host: wiki.example.com
    backend: http://localhost:3000
    app_id: app-wiki
```

## 手順

1. `cargo build --release` でビルド
2. Traefik labels から `volta-gateway.yaml` を作成
3. CF のオリジンを volta-gateway のポートに変更
4. テスト (`curl /healthz`, `/metrics`)
5. トラフィック切替（Traefik をフォールバックとして残す）
6. 安定確認後、Traefik を削除

## 失うもの / 得るもの

| 失うもの | 代替 |
|---------|------|
| ACME | Cloudflare |
| ロードバランシング | Phase N |
| WebSocket / gRPC | Phase N |
| ダッシュボード UI | `/metrics` (Prometheus) |

| 得るもの | 効果 |
|---------|------|
| 認証レイテンシ | 4-10ms → 0.5-1ms |
| リクエスト可視性 | SM 遷移ログ |
| 起動時間 | ~10ms (Rust) vs ~2s (Traefik) |
| メモリ | ~5MB vs ~50MB |
