# volta-gateway Backlog

> Source: [HANDOFF.md](./HANDOFF.md) (2026-04-07)

## Phase 5

| # | Feature | Status | Description | Depends on |
|---|---------|--------|-------------|------------|
| 1 | WebSocket TCP tunnel | ✅ complete | hyper::upgrade::on() 両側 + copy_bidirectional。serve_connection_with_upgrades 有効化 | — |
| 2 | Zero-downtime config reload | ✅ complete | ArcSwap<HotState> で routing+flow_def を atomic swap。SIGHUP で即時反映 | — |
| 3 | カスタムエラーページ | ✅ complete | config.error_pages_dir + HotState にプリロード。HTML 優先、JSON fallback | — |
| 4 | Per-route CORS config | ✅ complete | RouteEntry.cors_origins + Origin ヘッダ照合。Vary: Origin 対応 | — |

## Layer 3 (Day 2-30)

| # | Feature | Status | Description | Depends on |
|---|---------|--------|-------------|------------|
| 5 | Let's Encrypt ACME | ✅ complete | rustls-acme + tokio-rustls。config.tls で有効化、staging 対応 | — |
| 6 | Retry + circuit breaker | ✅ complete | CircuitBreaker (5 failures/30s recovery) + idempotent retry (GET/HEAD/OPTIONS) | — |
| 7 | Compression (gzip) | ✅ complete | flate2 gzip for text/json/xml/js。Accept-Encoding 判定、既存 content-encoding スキップ | — |
| 8 | Redirect middleware | ✅ complete | server.force_https + tls 設定で HTTP→HTTPS 301 リダイレクト | — |
| 9 | TCP/UDP proxy (L4) | ✅ complete | config.l4_proxy で TCP/UDP ポートフォワーディング。copy_bidirectional | — |
