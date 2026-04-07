# Spec: volta-gateway v0.3.0 — Tribunal Gap 実装仕様

> Generated: 2026-04-07
> Source: DGE Tribunal v5-v9 (5 rounds, 12 evaluators, 29 gaps)
> Status: Active gaps requiring implementation

---

## 1. Scope

v5-v9 の Active Gap から実装対象を抽出。3 カテゴリに分類:

| Category | Items | Priority |
|----------|-------|----------|
| **ACT-A**: 計測・実証 | 3 | 🔴 最優先 (論文主張の裏付け) |
| **ACT-B**: Integration test | 1 | 🟠 高 |
| **ACT-C**: 論文修正 | 3 | 🟡 中 |

---

## 2. ACT-A: 計測・実証

### ACT-A1: E2E ベンチマーク (GW-50, Critical)

**目的**: volta-gateway の req/sec, p99 レイテンシを実測し、論文の「5-10 倍高速」主張を検証または撤回する。

**方法**:
```bash
# 1. Mock backend (echo server)
# tests/bench_server.rs — tokio で 200 OK を即返す HTTP server

# 2. Mock volta-auth-proxy
# tests/bench_auth.rs — 200 + X-Volta-User-Id を即返す

# 3. volta-gateway 起動
# volta-gateway bench.yaml (mock auth + mock backend)

# 4. wrk ベンチマーク
wrk -t4 -c100 -d30s http://localhost:8080/api/test
wrk -t4 -c100 -d30s --latency http://localhost:8080/api/test
```

**計測項目**:
| Metric | Tool | Target |
|--------|------|--------|
| req/sec (throughput) | wrk -t4 -c100 | 記録 |
| avg latency | wrk | 記録 |
| p50 / p99 / p99.9 latency | wrk --latency | 記録 |
| auth check 時間 | metrics auth_duration_us_sum | < 1ms |
| SM overhead | criterion sm_start_flow | < 5μs |

**成果物**: `benches/e2e_results.md` に結果を記録。論文の Section 4.2 を実測値で更新。

### ACT-A2: Traefik 同条件比較 (GW-52, High)

**目的**: Traefik + localhost ForwardAuth と volta-gateway の同条件比較。

**方法**:
```yaml
# traefik-bench.yaml — 同じ mock auth + mock backend で Traefik を起動
# ForwardAuth middleware → localhost:7070/auth/verify

# 同一マシン、同一 wrk パラメータで計測
wrk -t4 -c100 -d30s http://localhost:8081/api/test  # Traefik
wrk -t4 -c100 -d30s http://localhost:8080/api/test  # volta-gateway
```

**成果物**: `benches/comparison.md` に Traefik vs volta-gateway の数値比較。
- 差が 5 倍以上 → 論文の主張を維持
- 差が 2-5 倍 → 主張を「2-5 倍」に修正
- 差が 2 倍未満 → 主張を撤回し、差別化ポイントを変更

### ACT-A3: SM overhead 計測 (GW-54 関連)

**目的**: tramli SM の per-request コストを定量化。

**方法**: criterion bench `sm_start_flow` の結果を取得 (既存)。加えて:
```rust
// benches/proxy_bench.rs に追加
fn bench_sm_full_lifecycle(c: &mut Criterion) {
    // start_flow → resume(auth) → resume(backend) の3ステップ
}
```

**成果物**: SM overhead を論文 Section 2.1 に「実測値: start_flow Xμs, full lifecycle Yμs」として追記。

---

## 3. ACT-B: Integration Test

### ACT-B1: HTTP Integration Test (GW-53, High)

**目的**: 実 HTTP リクエストを volta-gateway に投げ、proxy 動作を検証。

**実装**:
```rust
// tests/integration_test.rs

#[tokio::test]
async fn proxy_forwards_to_backend() {
    // 1. Mock backend (port 0 = OS 割当) — 200 OK + body
    // 2. Mock volta auth (port 0) — 200 + X-Volta-User-Id
    // 3. volta-gateway 起動 (ProxyService + hyper server, port 0)
    // 4. hyper client → gateway → backend
    // 5. Assert: status 200, body 一致, X-Volta-* strip 済み
}

#[tokio::test]
async fn proxy_returns_403_on_auth_denied() {
    // Mock volta → 403
    // Assert: gateway → 403
}

#[tokio::test]
async fn proxy_returns_502_on_backend_down() {
    // Mock volta → 200, backend = 接続拒否
    // Assert: gateway → 502
}

#[tokio::test]
async fn proxy_cors_preflight_returns_204() {
    // OPTIONS + Origin header + cors_origins 設定
    // Assert: 204 + Access-Control-Allow-Origin
}

#[tokio::test]
async fn proxy_circuit_breaker_returns_503() {
    // Backend を落とした状態で threshold 回リクエスト
    // Assert: 503 + Retry-After
}

#[tokio::test]
async fn proxy_rate_limit_returns_429() {
    // per_ip_rps を超えるリクエスト
    // Assert: 429 + Retry-After
}
```

**成果物**: `tests/integration_test.rs` (6テスト)。テスト合計 30 → 36。

---

## 4. ACT-C: 論文修正

### ACT-C1: Scope 明示 (GW-51, Medium)

論文 Section 1 に追記:
```markdown
### 1.4 Scope
本論文はプロキシ層で認証を行う SaaS アーキテクチャを対象とする。
認証をエッジ (Cloudflare Workers + KV) やデータベース層 (Supabase RLS) で
行うアーキテクチャは範囲外である。
```

### ACT-C2: 動機の修正 (GW-55, Medium)

Section 1 の Introduction を修正:
```markdown
### 1.0 Motivation
volta-gateway は volta-auth-proxy の companion として開発された。
Traefik + volta-auth-proxy の組み合わせは機能的に十分だが、
ForwardAuth middleware の設定が散在し (Docker labels + middleware chain + 
service 定義)、5-10 サービスの小規模 SaaS でも設定ファイルが複雑化する。
volta-gateway の動機は「認証レイテンシの最適化」と
「設定の簡潔さ」の両立である。
```

### ACT-C3: ベンチマーク結果反映 (ACT-A1/A2 完了後)

Section 4.2 を実測値で書き換え。「5-10 倍高速」が実証されない場合は主張を修正。

---

## 5. 実装順序

```
Step 1: ACT-B1 (integration test)     ← テスト基盤。全体の安全網
Step 2: ACT-A1 (E2E bench)            ← 自己計測。論文の根拠
Step 3: ACT-A3 (SM overhead)           ← SM のコスト定量化
Step 4: ACT-C1 + ACT-C2 (論文修正)    ← scope + 動機
Step 5: ACT-A2 (Traefik 比較)         ← 同条件比較 (Traefik 要インストール)
Step 6: ACT-C3 (ベンチ結果反映)        ← 全計測完了後に論文更新
```

**Step 1-4 はこのセッションで実装可能。Step 5 は Traefik のインストールが必要。**

---

## 6. Done の定義 (DD-003 準拠)

- [ ] Integration test 6件 PASS
- [ ] E2E bench 結果が `benches/e2e_results.md` に記録
- [ ] SM full lifecycle の criterion 結果あり
- [ ] 論文に scope + 動機の修正が反映
- [ ] 合計テスト 36+ PASS
