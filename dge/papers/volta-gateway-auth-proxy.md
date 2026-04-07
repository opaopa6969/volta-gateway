# volta-gateway: State-Machine-Driven Auth-Aware Reverse Proxy for Small-Scale SaaS

> Technical Paper — volta-gateway v0.2.0 (2026-04-07)
> For DGE Tribunal Review

## Abstract

認証処理を外部サービスに委譲する Forward Auth パターンは、リクエストごとに 4-10ms のネットワークオーバーヘッドを発生させる。volta-gateway は、認証サービス (volta-auth-proxy) を localhost にコロケーションし、コネクションプール経由で 0.5-1ms の認証レイテンシを実現する Rust 製リバースプロキシである。tramli ステートマシンによるリクエストライフサイクルの可視化、ArcSwap によるゼロダウンタイム設定リロード、30 テストと criterion ベンチマークによる品質保証を備える。5-20 サービス規模の SaaS を対象とし、Traefik/Envoy の大規模エコシステムとは明確に棲み分ける。

## 1. Introduction

### 1.0 Motivation

volta-gateway は volta-auth-proxy の companion として開発された。Traefik + volta-auth-proxy の組み合わせは機能的に十分だが、ForwardAuth middleware の設定が散在し (Docker labels + middleware chain + service 定義)、5-10 サービスの小規模 SaaS でも設定ファイルが複雑化する。volta-gateway の動機は「認証レイテンシの最適化」と「設定の簡潔さ」の両立である。

### 1.1 The Auth Latency Problem

マイクロサービスアーキテクチャにおける認証は、リバースプロキシが外部認証サービスに問い合わせる Forward Auth パターンが主流である。Traefik の ForwardAuth、Caddy の forward_auth、NGINX の auth_request — いずれもリクエストごとに 1 回のネットワークラウンドトリップを追加する。

計測されたオーバーヘッド:
- **Traefik ForwardAuth**: 4-10ms/request (2 ネットワークホップ)
- **NGINX auth_request**: 2-10ms+ (キャッシュなし。1 ページあたり最大 12 サブリクエストの報告あり)
- **OAuth2 Proxy**: 760-950ms (トークン操作含む)
- **サイドカーパターン全般**: RPC レイテンシ 2-6 倍増、スループット 50-90% 低下 (K8sidecar, 2025)

10 サービスの SaaS で 1 リクエストが 3 サービスを経由する場合、認証だけで 12-30ms が消費される。これはユーザー体験に直接影響する p99 レイテンシの大部分を占めうる。

### 1.2 The Caching Dilemma

認証レスポンスのキャッシュは レイテンシを削減するが、revoke されたセッションがキャッシュ TTL 内で有効なまま残る「stale-auth」リスクを導入する。これは Forward Auth モデルの根本的なトレードオフであり、クリーンな解決策が存在しない。

### 1.25 Scope

本論文はプロキシ層で認証を行う SaaS アーキテクチャを対象とする。認証をエッジ (Cloudflare Workers + KV) やデータベース層 (Supabase RLS) で行うアーキテクチャは範囲外である。これらのアプローチはプロキシ層の認証レイテンシ問題を「解消」するが、既存の Forward Auth ベースのインフラからの移行コストが大きく、多くの小規模 SaaS は依然としてプロキシ層認証に依存している。

### 1.3 Contribution

volta-gateway は以下のアプローチでこの問題に取り組む:
1. **localhost コロケーション**: 認証サービスを同一ホストに配置し、ネットワークレイテンシを排除
2. **コネクションプール**: HTTP 接続を再利用し、TCP ハンドシェイクコストを排除
3. **fail-closed**: 認証不能時は 502 を返却。キャッシュによる stale-auth を回避
4. **ステートマシン可視化**: リクエストの各段階 (受信→検証→ルーティング→認証→転送→完了) をマイクロ秒精度で計測

## 2. Architecture

### 2.1 Request Lifecycle (B-pattern)

volta-gateway は tramli ステートマシンを「判断エンジン」として使い、非同期 I/O を SM の外で実行する B-pattern を採用する:

```
Client → [RECEIVED] →sync→ [VALIDATED] →sync→ [ROUTED]
  →async→ volta auth check (0.5-1ms)
  →sync→ [AUTH_CHECKED]
  →async→ backend forward (varies)
  →sync→ [FORWARDED] →sync→ [COMPLETED] → Client
```

SM は同期実行 (~1μs) で、非同期 I/O はその外側。SM が状態遷移の正しさを保証し、非同期ランタイムが性能を担保する。

### 2.2 Auth Integration

```
volta-gateway → HTTP GET localhost:7070/auth/verify
  Headers: Cookie, X-Forwarded-Host/Uri/Proto, X-Volta-App-Id
  Response: X-Volta-User-Id, X-Volta-Email, X-Volta-Tenant-Id
  Timeout: 500ms (fail-closed)
  Pool: 32 idle connections/host
```

localhost 通信 + コネクションプールにより、認証チェックのレイテンシは 0.5-1ms。Traefik ForwardAuth (4-10ms) の 5-10 倍高速。

### 2.3 Zero-Downtime Config Reload

`ArcSwap<HotState>` により、SIGHUP シグナルで routing table + flow definition + error pages + CORS 設定を atomic に swap する。in-flight リクエストは旧 config で完了し、新規リクエストから新 config が適用される。ロック不要、レイテンシスパイクなし。

### 2.4 Feature Matrix

| Feature | Implementation |
|---------|---------------|
| HTTP/1.1 + HTTP/2 | hyper 1.x auto::Builder |
| WebSocket tunnel | hyper::upgrade + copy_bidirectional (1024 接続上限) |
| TLS/ACME | rustls-acme (Let's Encrypt, staging 対応) |
| Load balancing | Round-robin (BackendSelector) |
| Rate limiting | Global + per-IP (1000/100 rps デフォルト) |
| Circuit breaker | 5 failures / 30s recovery, idempotent retry |
| Compression | gzip (flate2), text/json/xml/js, 1MB 閾値 |
| CORS | Per-route origins, secure-by-default (no implicit wildcard) |
| Error pages | Custom HTML directory, JSON fallback |
| L4 proxy | TCP/UDP ポートフォワーディング |
| Metrics | Prometheus exposition (WebSocket/CB/compression/L4) |

## 3. Related Work

### 3.1 General-Purpose Reverse Proxies

| Proxy | Lang | Auth Model | Auth Latency | Config (5-10 svc) | ACME |
|-------|------|------------|-------------|-------------------|------|
| Traefik | Go | ForwardAuth | 4-10ms | Medium | Built-in |
| Caddy | Go | forward_auth | 3-8ms est. | **Low** | **Best-in-class** |
| NGINX | C | auth_request | 2-10ms+ | High | External |
| Envoy | C++ | ext_authz (gRPC) | <100ms | Very High | External |

Caddy は設定の簡潔さと ACME で優れるが、auth は外部依存。Traefik は Kubernetes/Docker エコシステムで圧倒的だが、小規模 SaaS には過剰。NGINX は raw performance で最速 (8.10ms avg) だが、ACME なし・静的設定。Envoy は service mesh 向けで小規模には不適。

### 3.2 Auth-Specialized Proxies

| Proxy | Lang | Auth Model | Latency | 特徴 |
|-------|------|------------|---------|------|
| OAuth2 Proxy | Go | Standalone OAuth2 | 760-950ms | CNCF Sandbox。全 OAuth フロー内蔵 |
| Pomerium | Go | Built-in (inline) | Low (session) | Zero-trust。デバイス認証。$18M Series A |
| Ory Oathkeeper | Go | Pipeline (rule) | Sub-ms (JWT local) | Authenticate→Authorize→Mutate パイプライン |
| Authelia | Go | Portal (forward-auth) | "milliseconds" | <20MB container。Passkey 対応 |

Pomerium は最も完全な zero-trust だが、multi-component architecture で小規模には重い。Oathkeeper は JWT ローカル検証でサブミリ秒だが、Ory エコシステムとの結合が前提。Authelia は軽量だが、ホストプロキシ (Traefik/NGINX) に依存。

### 3.3 Rust-Based Proxies

| Project | Description | Auth | Scale |
|---------|-------------|------|-------|
| Pingora (Cloudflare) | フレームワーク。1T+ req/day。NGINX 比 70% CPU 削減 | なし (ライブラリ) | 惑星規模 |
| Pingap | Pingora ベース。20+ プラグイン | プラグイン | 中-大 |
| River (ISRG) | メモリ安全プロキシ。Pingora ベース | 最小限 | 大 |

Pingora は圧倒的な性能だが「フレームワーク」であり、そのまま使えるプロキシではない。volta-gateway は Pingora に依存せず、hyper 1.x を直接使うことで依存グラフを最小化している。

### 3.4 Positioning

volta-gateway は **「Caddy の設定簡潔さ」+「Oathkeeper の認証パイプライン」+「Pingora の Rust ランタイム」** の交差点を狙う:

```
                    大規模 (50+ svc)
                    │
            Envoy ──┤── Traefik
                    │
                    │        Pomerium
                    │       ╱
    Zero-trust ─────┤──────╱── volta-gateway ← ここ
                    │     ╱
                    │    ╱
            Caddy ──┤───── Authelia
                    │
                    小規模 (5-20 svc)
```

## 4. Quality Assurance

### 4.1 Testing

- **35 テスト**: SM lifecycle (8), circuit breaker (4), compression (4), CORS (4), config validation (8), error pages (2), **integration (5)**
- **Integration tests**: 実 HTTP リクエスト → proxy → backend (200 forward, 403 auth denied, 502 backend down, 204 CORS preflight, 429 rate limit)
- **DGE Tribunal**: 5 ラウンド、12 人の評価者、29 Gap 発見、7 修正、3 Design Decision
- **GW-36 (Critical)**: compression でレスポンスヘッダ (Set-Cookie, Cache-Control) が消失するバグを発見・修正

### 4.2 Benchmarks

#### Micro-benchmarks (criterion)

| Operation | Latency |
|-----------|---------|
| SM start_flow | **707 ns** |
| SM full lifecycle (start + 2x resume) | **1.69 μs** |
| Routing lookup (exact) | **11 ns** |
| Routing lookup (wildcard) | **61 ns** |
| Compression check | **5 ns** |

#### E2E Benchmarks (oha, release build, localhost mock auth + backend)

| Metric | volta-gateway | Direct backend | Proxy overhead |
|--------|--------------|----------------|----------------|
| p50 | **0.252 ms** | 0.203 ms | **40 μs** |
| p99 | 1.235 ms | 0.298 ms | 858 μs |
| avg | 0.395 ms | 0.209 ms | 171 μs |

SM overhead (1.69μs) は total proxy overhead (171μs) の約 1%。auth round-trip (localhost HTTP) が支配的。

#### Traefik 同条件比較 (GW-52)

同一 localhost mock auth + mock backend。Traefik v3.4 (Docker) + ForwardAuth vs volta-gateway (native release)。

| Metric | volta-gateway | Traefik + ForwardAuth | Ratio |
|--------|--------------|----------------------|-------|
| **p50** | **0.252 ms** | **1.673 ms** | **6.6x faster** |
| avg | 0.395 ms | 1.777 ms | 4.5x faster |
| p99 | 1.235 ms | 2.373 ms | 1.9x faster |
| req/sec | 2,501 | 561 | 4.5x higher |

p50 で 6.6 倍、avg で 4.5 倍。tail latency (p99) では差が 1.9 倍に縮まる (OS スケジューリング + TCP stack overhead が支配的)。

### 4.3 Security Decisions

- **CORS**: デフォルトは「ヘッダなし」(DD-001)。明示的な `cors_origins: ["*"]` が必要
- **fail-closed**: volta down = 502。認証バイパス経路なし
- **X-Volta-\* strip**: backend レスポンスから X-Volta-\* を除去 (forgery 防止)
- **WebSocket 制限**: 1024 同時接続上限 (fd 枯渇防止)

## 5. Limitations and Future Work

### 5.1 Known Limitations

1. **SM overhead**: リクエストごとに InMemoryFlowStore を alloc/dealloc (1.69μs)。100K+ req/sec では共有 engine を検討すべき
2. **proxy.rs の肥大化**: 600 行超。circuit breaker / compression / CORS が同一ファイル
3. **L4 proxy に認証なし**: TCP/UDP は認証対象外 (DD-002)。IP 制限で保護
4. **ベンチマーク環境**: WSL2 上の計測。bare metal では異なる結果が予想される
5. **Traefik 比較の公平性**: Traefik は Docker 内 (~0.1-0.3ms overhead)、volta-gateway は native。native Traefik binary との比較は未実施

### 5.2 Future Work

- **Caddy/NGINX との定量比較**: 同条件 localhost auth benchmark
- **proxy.rs 分割**: circuit_breaker.rs, compression.rs, cors.rs
- **L4 IP allowlist**: config ベースの IP 制限 (DD-002)
- **Brotli compression**: gzip に加えて Accept-Encoding: br 対応
- **Weighted round-robin**: backend ごとの重み付け LB
- **bare metal ベンチマーク**: WSL2 以外の環境での再計測

## 6. Conclusion

volta-gateway は、小規模 SaaS における認証レイテンシの問題に対して、localhost コロケーション + コネクションプール + fail-closed という実用的なアプローチを提供する。

同条件ベンチマーク (localhost mock auth + backend) により、Traefik ForwardAuth との定量比較を実施した:
- **p50: 6.6 倍高速** (0.252ms vs 1.673ms)
- **avg: 4.5 倍高速** (0.395ms vs 1.777ms)
- **SM overhead: total の 1%** (1.69μs / 171μs)

5 ラウンドの DGE Tribunal (29 Gap, 12 人の評価者) を経て、Critical バグ (compression ヘッダ消失) の発見・修正、CORS secure-by-default への変更、Host 正規化の統一を行った。35 テスト (unit + integration) + criterion ベンチマーク基盤を整備。

volta-gateway は Traefik の代替ではない。「50+ サービスの Kubernetes クラスタ」には Traefik + volta-auth-proxy を推奨する。volta-gateway が勝つのは「5-20 サービスの SaaS で、認証レイテンシと設定の簡潔さが最優先」というニッチだ。

---

**References**

- Traefik ForwardAuth: https://doc.traefik.io/traefik/middlewares/http/forwardauth/
- Caddy forward_auth: https://caddyserver.com/docs/caddyfile/directives/forward_auth
- NGINX auth_request: https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
- Envoy ext_authz: https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
- Cloudflare Pingora: https://github.com/cloudflare/pingora
- Pomerium: https://docs.pomerium.com/docs/internals/architecture
- Ory Oathkeeper: https://github.com/ory/oathkeeper
- Authelia: https://www.authelia.com/overview/prologue/architecture/
- K8sidecar overhead (2025): https://onlinelibrary.wiley.com/doi/full/10.1002/spe.3423
- Proxy benchmarks: https://homelabsec.com/posts/nginx-vs-caddy-vs-traefik-benchmark-results/
- tramli SM engine: https://crates.io/crates/tramli
