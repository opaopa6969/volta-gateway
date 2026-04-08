# volta-gateway Backlog

> Last updated: 2026-04-08

## Completed (Day 1-2)

<details>
<summary>Phase 5 + Layer 3 (9件)</summary>

| # | Feature |
|---|---------|
| 1 | WebSocket TCP tunnel |
| 2 | Zero-downtime config reload (ArcSwap) |
| 3 | カスタムエラーページ |
| 4 | Per-route CORS config |
| 5 | Let's Encrypt ACME |
| 6 | Retry + circuit breaker |
| 7 | Compression (gzip) |
| 8 | HTTP→HTTPS redirect |
| 9 | TCP/UDP proxy (L4) |
</details>

<details>
<summary>DGE tribunal fixes (7件)</summary>

GW-36 compression ヘッダ消失, GW-29/38 force_https 除外, GW-30 CORS preflight, GW-44 CORS deny-default, GW-45 Host 正規化, GW-37 WebSocket 接続制限
</details>

<details>
<summary>v0.2.0 (7件)</summary>

GW-27 metrics 拡充, GW-33 config validation, GW-34/43 config docs, GW-46 Retry-After, GW-49 benchmark, GW-40 テスト追加
</details>

<details>
<summary>v0.3.0 bench + paper (7件)</summary>

Integration test 5件, E2E bench (p50 0.252ms), Traefik比較 (6.6x), SM bench (1.69μs), 論文 scope/動機修正, dead code cleanup
</details>

<details>
<summary>Code review fixes (4件)</summary>

CR-2 RateLimiter race, CR-5 per-host LB, CR-6 metrics wiring, CR-7 normalize_host
</details>

<details>
<summary>v0.5.0 プロダクト進化 (5件)</summary>

PROD-1 health check, PROD-2 admin API, PROD-3 HTTP reload, PROD-4 CF trust, PROD-5 histogram
</details>

<details>
<summary>GitHub Issues #1-28 (28件)</summary>

#1 public routes + bypass paths, #2 traffic mirroring, #3 path rewrite, #4 header manipulation, #5 access log, #6 weighted routing, #7 traceparent, #8 response cache, #9 mTLS, #10 geo control, #11 plugin system, #12 README Docker labels section, #13 ConfigSource trait, #14 Middleware Extension, #15 Docker labels source, #16 services.json source, #17 HTTP polling, #18-28 bug fixes (11件)
</details>

<details>
<summary>GitHub Issues #33-38 (5件)</summary>

#33 auth cache, #34 backpressure semaphore, #35 per-route timeout, #36 --validate, #38 /admin/stats
</details>

**Total completed: ~72 items. 80 tests. 30 features.**

## Open — GitHub Issues

| # | Issue | Category | Priority |
|---|-------|----------|----------|
| #37 | Streaming compression (async-compression) | 機能 | 🟡 Medium |
| #39 | Access log file separation (tracing-appender) | 運用 | 🟡 Medium |
| #42 | traefik-to-volta config converter (STR-10) | ツール | 🔴 Critical |
| #43 | ACME DNS-01 + zero-config HTTPS (STR-2/3) | 機能 | 🟠 High |
| #44 | Docker labels source — full Docker API (STR-4) | 機能 | 🟠 High |
| #45 | Getting Started guide (STR-7) | DX | 🟠 High |
| #46 | README messaging rewrite (STR-6) | マーケ | 🟠 High |
| #47 | Traefik vs volta benchmark article (STR-11) | マーケ | 🟠 High |

## Open — Technical Debt (v0.4.0)

| # | Item | Severity |
|---|------|----------|
| CR-8 | // path rejection 緩和 | ✅ 済 (#24) |
| CR-10 | HTTPS backend (mTLS module ready) | 🟡 Medium |
| GW-39 | proxy.rs 分割 (1,100行超) | 🟡 Medium |
| GW-41 | L4 proxy IP 制限 | 🟡 Medium |
| PROD-6 | Chunked body Limited | 🟡 Medium |

## Open — Strategic (DD-004/005)

| # | Item | Phase | Priority |
|---|------|-------|----------|
| MIG-1 | Auth verify in-process (JWT in gateway) | DD-005 Ph0 | 🔴 最優先 |
| MIG-3 | 並行運用戦略 (Rust read + Java write) | DD-005 Ph1 | 🟠 High |
| STR-5 | docker-compose → services.json 自動生成 | DD-004 | 🟡 Medium |
| STR-8 | Caddy 差別化 (エコシステム訴求) | DD-004 | 🟡 Medium |
| STR-9 | volta-console 統合デモ | DD-004 | 🟡 Medium |
| MIG-2 | SAML: Rust or Java sidecar 判断 | DD-005 Ph3 | 🟡 Medium |
| MIG-4 | volta single binary vision | DD-005 Ph4 | 🟢 Low |
| Wasm | Plugin system Wasm runtime (wasmtime) | — | 🟢 Low |

## Design Decisions

- [DD-001](../dge/decisions/DD-001-cors-default-deny.md) — CORS デフォルトを deny に変更
- [DD-002](../dge/decisions/DD-002-l4-proxy-scope.md) — L4 proxy は認証対象外
- [DD-003](../dge/decisions/DD-003-accept-criteria.md) — v0.1.0 Accept 基準
- [DD-004](../dge/decisions/DD-004-traefik-user-acquisition.md) — Traefik ユーザー獲得戦略
- [DD-005](../dge/decisions/DD-005-java-to-rust-migration.md) — volta-auth-proxy Java→Rust 段階的移行
