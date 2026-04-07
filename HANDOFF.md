# Session Handoff: volta-gateway

> From: volta-auth-proxy セッション (2026-04-07)
> To: volta-gateway 次回セッション

## 現状

Phase 1-4 が1セッションで完了。8テスト PASS、E2E 動作確認済み。

### 完了済み

| Phase | 内容 |
|-------|------|
| 1 | HTTP proxy + tramli SM routing + volta auth + security headers + graceful shutdown (30s drain) |
| 2 | HTTP/2 (auto::Builder) + per-IP rate limit (GC付) + Prometheus /metrics + config validation + IP allowlist (ipnet CIDR) + connection pool config + chunked body 10MB |
| 3 | Round-robin LB (backends: []) + CORS + SIGHUP reload notification + pretty log + IPv6 Host + README positioning |
| 4 | WebSocket module (auth + routing, TCP tunnel は未完) + IP allowlist enforcement in SM |

### ファイル構成

```
src/
  main.rs       サーバー起動, /healthz, /metrics, graceful shutdown, SIGHUP
  config.rs     YAML config + validate() + routing_table() + ip_allowlist_table()
  state.rs      ProxyState enum (tramli FlowState impl)
  flow.rs       FlowDefinition + RequestValidator + RoutingResolver + Guards
  proxy.rs      ProxyService (SM 駆動, B方式) + RateLimiter + BackendSelector
  auth.rs       VoltaAuthClient (connection pool, 500ms timeout, fail-closed)
  metrics.rs    Prometheus /metrics (crate 不要, AtomicU64)
  websocket.rs  WebSocket upgrade handler (auth + routing, tunnel は Phase 5)
  lib.rs        module declarations

tests/
  flow_test.rs  8 tests (SM lifecycle, routing, validation, LB)

docs/
  migration-from-traefik.md     en
  migration-from-traefik-ja.md  ja
```

### 依存

```toml
tramli = "0.1"     # SM engine (crates.io)
hyper = "1"        # HTTP server/client
hyper-util = "0.1" # auto::Builder, TokioExecutor
tokio = "1"        # async runtime
tower = "0.5"      # middleware (未使用だが Phase 5 で活用)
ipnet = "2"        # CIDR parsing
arc-swap = "1"     # hot reload (未使用だが Phase 5 で活用)
serde + serde_yaml # config
tracing            # logging
uuid               # request ID
```

## やるべきこと (優先順)

### Phase 5 (次のセッション)

1. **WebSocket TCP tunnel** — `websocket.rs` の `handle_websocket()` に実装。hyper::upgrade::on() で client/backend 両側を upgrade → tokio::io::copy_bidirectional。tokio-tungstenite crate を検討
2. **Zero-downtime config reload** — `arc-swap` で routing table を atomic swap。SIGHUP → config 再読込 → ArcSwap::store() → 次のリクエストから新 routing 適用
3. **カスタムエラーページ** — config に `error_pages_dir: /path/to/html/`。502.html, 403.html 等。なければ JSON fallback
4. **Per-route CORS config** — routing に `cors_origins: ["https://app.example.com"]`。今は全レスポンスに `*`

### Layer 3 (Day 2-30)

5. **Let's Encrypt ACME** — `rustls-acme` crate。CF なしの環境向け
6. **Retry + circuit breaker** — tower::retry + tower::limit。backend failure 時に自動 retry
7. **Compression (gzip, brotli)** — tower-http::compression
8. **Redirect middleware** — HTTP → HTTPS 強制
9. **TCP/UDP proxy (L4)** — SM とは別レイヤー

### DGE セッション

```
volta-auth-proxy/dge/sessions/ に以下がある:
  2026-04-07-rust-sm-proxy.md          Round 1: メリット + Auth 方式
  2026-04-07-rust-sm-proxy-r2.md       Round 2: スコープ + Auth 詳細
  2026-04-07-rust-sm-proxy-r3.md       Round 3: L7 防御 + tower 統合
  2026-04-07-gateway-tribunal.md       Tribunal v1: 14 gaps
  2026-04-07-gateway-tribunal-v2.md    Tribunal v2: Accept
  2026-04-07-gateway-tribunal-v3.md    Tribunal v3: Phase 2 Accept
  2026-04-07-gateway-tribunal-v4.md    Tribunal v4: 厳しい声 (SRE Reject)
  2026-04-07-gateway-phase2-design.md  Phase 2 設計
```

Spec: `volta-auth-proxy/dge/specs/volta-gateway.md`

### 重要な設計判断

1. **SM は sync** — tramli は意図的に同期。async I/O は SM の外 (B方式)。`docs/async-integration.md` 参照
2. **Traefik の代替ではない** — 小規模 SaaS 向け認証特化 proxy。大規模は Traefik + volta-auth-proxy
3. **fail-closed** — volta が落ちたら 502。認証できないなら通さない
4. **X-Volta-* strip** — backend のレスポンスから X-Volta-* を除去（forgery 防止）
5. **Per-request FlowEngine** — リクエストごとに InMemoryFlowStore を生成。100K+ req/sec では共有 engine を検討

### volta-auth-proxy との接続

```
volta-gateway → HTTP GET localhost:7070/auth/verify
  Headers: Cookie, X-Forwarded-Host/Uri/Proto, X-Volta-App-Id
  Response: X-Volta-User-Id, X-Volta-Email, X-Volta-Tenant-Id, etc.
  Timeout: 500ms
  Fail: 502 Bad Gateway

volta-gateway → HTTP GET localhost:7070/healthz
  Response: {"status":"ok"}
```

### tramli のレビュー

`tramli/docs/review-volta-gateway.md` に使用感レビューあり。
改善提案: GuardOutput::accepted! マクロ、per-request engine alloc。

### テスト実行

```bash
cargo test                           # 8 tests
cargo run -- volta-gateway.yaml      # 起動
curl localhost:8080/healthz          # health check
curl localhost:8080/metrics          # Prometheus
```
