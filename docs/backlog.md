# volta-gateway Backlog

> Source: [HANDOFF.md](./HANDOFF.md) + DGE tribunal v5-v8 (2026-04-07)

## Phase 5

| # | Feature | Status | Description |
|---|---------|--------|-------------|
| 1 | WebSocket TCP tunnel | ✅ complete | hyper::upgrade 両側 + copy_bidirectional |
| 2 | Zero-downtime config reload | ✅ complete | ArcSwap\<HotState\> SIGHUP 即時反映 |
| 3 | カスタムエラーページ | ✅ complete | error_pages_dir + HTML/JSON fallback |
| 4 | Per-route CORS config | ✅ complete | cors_origins + Origin 照合 + Vary: Origin |

## Layer 3

| # | Feature | Status | Description |
|---|---------|--------|-------------|
| 5 | Let's Encrypt ACME | ✅ complete | rustls-acme + tokio-rustls, staging 対応 |
| 6 | Retry + circuit breaker | ✅ complete | 5 failures / 30s recovery + idempotent retry |
| 7 | Compression (gzip) | ✅ complete | flate2, into_parts() ヘッダ保持, 1MB 閾値 |
| 8 | HTTP→HTTPS redirect | ✅ complete | force_https, healthz/metrics/.well-known 除外 |
| 9 | TCP/UDP proxy (L4) | ✅ complete | config.l4_proxy ポートフォワーディング |

## DGE tribunal 修正済み (v0.1.0 blockers)

| Gap | Description | Status |
|-----|-------------|--------|
| GW-36 | compression ヘッダ消失 (Critical) | ✅ into_parts() で修正 |
| GW-29 | force_https が /healthz 巻き込み | ✅ 除外パス追加 |
| GW-38 | force_https が ACME チャレンジ巻き込み | ✅ /.well-known/ 除外 |
| GW-30 | CORS preflight (OPTIONS) 未処理 | ✅ proxy で 204 返却 |
| GW-44 | CORS デフォルト wildcard | ✅ ヘッダなしに変更 (DD-001) |
| GW-45 | Host 正規化不整合 | ✅ config で to_lowercase() |
| GW-37 | WebSocket 接続数制限なし | ✅ 1024 上限 + RAII guard |

## v0.2.0 完了

| Gap | Description | Status |
|-----|-------------|--------|
| GW-27 | metrics 拡充 | ✅ WS/CB/compression/L4 カウンタ追加 |
| GW-33 | config validation | ✅ tls/l4_proxy/force_https/backends 検証 |
| GW-34 | config ドキュメント | ✅ volta-gateway.full.yaml (全フィールド) |
| GW-43 | minimal config サンプル | ✅ volta-gateway.minimal.yaml |
| GW-46 | circuit open 時 Retry-After | ✅ 503 + Retry-After ヘッダ |
| GW-49 | ベンチマーク基盤 | ✅ criterion, SM/routing/compression bench |
| GW-40 | テスト追加 | ✅ 30テスト (config validation 5件追加) |

## やらない / 設計判断 (DD)

| # | Gap | Reason |
|---|-----|--------|
| GW-28 | compression 最大サイズ | ✅ 1MB 閾値で対応済み |
| GW-31 | CB 閾値 config 化 | デフォルトで十分 |
| GW-32 | L4 graceful shutdown | L4 は補助機能 |
| GW-35 | service ハンドラ重複 | リファクタ時に解消 |
| GW-39 | proxy.rs 分割 | 機能安定後 |
| GW-47 | dead code warnings | cleanup タスク |
| GW-41 | L4 IP 制限 | DD-002 方針決定済み |
| GW-42 | URI unwrap_or_default | 低リスク |

## Design Decisions

- [DD-001](../dge/decisions/DD-001-cors-default-deny.md) — CORS デフォルトを deny に変更
- [DD-002](../dge/decisions/DD-002-l4-proxy-scope.md) — L4 proxy は認証対象外
- [DD-003](../dge/decisions/DD-003-accept-criteria.md) — v0.1.0 Accept 基準
