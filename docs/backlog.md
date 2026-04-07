# volta-gateway Backlog

> Last updated: 2026-04-07

## Completed

### Phase 5
| # | Feature | Description |
|---|---------|-------------|
| 1 | WebSocket TCP tunnel | hyper::upgrade 両側 + copy_bidirectional |
| 2 | Zero-downtime config reload | ArcSwap\<HotState\> SIGHUP 即時反映 |
| 3 | カスタムエラーページ | error_pages_dir + HTML/JSON fallback |
| 4 | Per-route CORS config | cors_origins + Origin 照合 + Vary: Origin |

### Layer 3
| # | Feature | Description |
|---|---------|-------------|
| 5 | Let's Encrypt ACME | rustls-acme + tokio-rustls, staging 対応 |
| 6 | Retry + circuit breaker | 5 failures / 30s recovery + idempotent retry |
| 7 | Compression (gzip) | flate2, into_parts() ヘッダ保持, 1MB 閾値 |
| 8 | HTTP→HTTPS redirect | force_https, healthz/metrics/.well-known 除外 |
| 9 | TCP/UDP proxy (L4) | config.l4_proxy ポートフォワーディング |

### DGE tribunal 修正 (v0.1.0 blockers)
| Gap | Description |
|-----|-------------|
| GW-36 | compression ヘッダ消失 — into_parts() で修正 |
| GW-29/38 | force_https 除外パス (healthz, metrics, .well-known) |
| GW-30 | CORS preflight (OPTIONS) proxy で 204 返却 |
| GW-44 | CORS デフォルト deny (DD-001) |
| GW-45 | Host 正規化 to_lowercase() 統一 |
| GW-37 | WebSocket 1024 接続上限 + RAII guard |

### v0.2.0
| Gap | Description |
|-----|-------------|
| GW-27 | metrics 拡充 (WS/CB/compression/L4) |
| GW-33 | config validation (tls/l4/force_https/backends) |
| GW-34 | config リファレンス (volta-gateway.full.yaml) |
| GW-43 | minimal config サンプル |
| GW-46 | circuit open 時 503 + Retry-After |
| GW-49 | criterion ベンチマーク基盤 |
| GW-40 | テスト追加 (22 unit + 8 flow + 5 integration = 35) |

### v0.3.0 (Spec ACT + ベンチ)
| ACT | Description |
|-----|-------------|
| ACT-B1 | Integration test 5件 (HTTP through proxy) |
| ACT-A1 | E2E bench: p50 0.252ms, overhead 40μs |
| ACT-A2 | Traefik 比較: p50 6.6x faster |
| ACT-A3 | SM full lifecycle: 1.69μs |
| ACT-C1/C2 | 論文 scope + 動機修正 |
| ACT-C3 | 論文にベンチ実測値反映 |
| GW-47 | dead code warnings 0 |

### Code review fixes
| # | Description |
|---|-------------|
| CR-2 | RateLimiter 競合 — Mutex<(u64, Instant)> に統一 |
| CR-5 | BackendSelector per-host HashMap カウンタ |
| CR-6 | metrics record_status/record_duration を handle() で呼出 |
| CR-7 | normalize_host() 共通関数化 (proxy/websocket 重複解消) |

## v0.4.0 backlog

| # | Item | Category | Severity | Description |
|---|------|----------|----------|-------------|
| CR-8 | `//` path rejection 緩和 | 互換性 | 🟡 Medium | `/api/v1//users` を弾くのは厳しすぎる。nginx 正規化済みパスへの対応検討 |
| CR-10 | HTTPS backend 対応 | 機能 | 🟡 Medium | `build_http()` のみ → hyper-rustls で remote HTTPS backend 対応 |
| GW-39 | proxy.rs 分割 | 保守性 | 🟡 Medium | 700行超 → circuit_breaker.rs, compression.rs, cors.rs |
| GW-41 | L4 proxy IP 制限 | セキュリティ | 🟡 Medium | DD-002 方針決定済み。config ベースの IP allowlist |
| GW-53+ | Integration test 拡充 | 品質 | 🟡 Medium | WebSocket tunnel, L4 proxy の integration test |
| BENCH-1 | Traefik native binary 比較 | 計測 | 🟢 Low | Docker overhead 排除した同条件比較 |
| BENCH-2 | Caddy/NGINX 同条件比較 | 計測 | 🟢 Low | 競合全プロダクトとの定量比較 |
| GW-32 | L4 graceful shutdown | 運用 | 🟢 Low | shutdown signal で新規 accept 停止 |
| GW-35 | service ハンドラ重複 | 保守性 | 🟢 Low | tls.rs / main.rs → proxy.rs 分割時に解消 |
| GW-42 | URI unwrap_or_default | セキュリティ | 🟢 Low | 不正入力で予想外ルーティングのリスク (低) |
| GW-54 | SM 遷移ログ活用事例 | DX | 🟢 Low | Grafana ダッシュボード等の実運用例 |

## v0.5.0 backlog (プロダクト進化)

| # | Item | Category | Severity | Description |
|---|------|----------|----------|-------------|
| PROD-1 | Backend health check + 自動切り離し | 運用 | 🟠 High | HealthCheckConfig 実装。per-backend AtomicBool alive flag、バックグラウンド定期 ping、BackendSelector で dead skip |
| PROD-2 | Admin API | 運用 | 🟠 High | `GET /admin/routes` (routing table), `GET /admin/backends` (health + pool), `POST /admin/drain` (graceful)。ip_allowlist 127.0.0.1/8 制限。volta-console service card 連携 |
| PROD-3 | HTTP reload endpoint | 運用 | 🟠 High | `POST /admin/reload` — SIGHUP に加えて HTTP 経由で config reload。volta-console から curl 一発 |
| PROD-4 | CF-Connecting-IP trusted proxy | セキュリティ | 🟠 High | trusted_proxies config。CF-Connecting-IP があれば client_ip として採用。FraudAlert JA3/JA4 連携の前提 |
| PROD-5 | Metrics histogram | 可観測性 | 🟡 Medium | AtomicU64 bucket カウンタ (1ms/5ms/25ms/100ms/500ms/1s/5s)。route 別ラベル。Grafana latency 分布 |
| PROD-6 | Chunked body Limited | セキュリティ | 🟡 Medium | `http_body_util::Limited` で body をラップ。content-length なし chunked の 10MB すり抜け対策 |

## Design Decisions

- [DD-001](../dge/decisions/DD-001-cors-default-deny.md) — CORS デフォルトを deny に変更
- [DD-002](../dge/decisions/DD-002-l4-proxy-scope.md) — L4 proxy は認証対象外
- [DD-003](../dge/decisions/DD-003-accept-criteria.md) — v0.1.0 Accept 基準
