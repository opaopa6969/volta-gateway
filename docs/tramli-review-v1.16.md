# tramli v1.16 Review — volta-gateway からの使用感レポート

> Date: 2026-04-08
> Reviewer: volta-gateway team
> tramli version: 0.1.0 → 1.16.0
> volta-gateway: 3,658 行, 64 テスト, 12 SM 状態, 5 プロセッサ, 2 ガード

## Summary

volta-gateway は tramli を HTTP リクエストライフサイクルのステートマシンとして使用している。0.1.0 から 1.16.0 へのアップグレードは **ゼロ破壊的変更** で完了した（コードの変更なしでコンパイル + 全テスト PASS）。新機能の `requires!` マクロと `strict_mode` を追加で採用した。

## What We Use

| tramli feature | volta-gateway での使用 |
|---------------|----------------------|
| `Builder` | プロキシフロー定義（8行で 12 状態 + 5 遷移） |
| `FlowEngine` | per-request SM 実行 (start → resume → resume) |
| `InMemoryFlowStore` | per-request 一時ストア |
| `StateProcessor` | RequestValidator, RoutingResolver, CompletionProcessor |
| `TransitionGuard` | AuthGuard, ForwardGuard (External 遷移) |
| `FlowContext` | 型安全なリクエストデータ受け渡し |
| `FlowDefinition` | Arc でクローン、ArcSwap で hot reload |
| **`requires!`** | **v1.16 新規採用** — TypeId ボイラープレート削減 |
| **`strict_mode`** | **v1.16 新規採用** — produces() の runtime 検証 |

## B-Pattern (sync SM + async I/O)

tramli の最大の価値は「同期で速い」こと。volta-gateway は B-pattern を採用:

```
engine.start_flow()   → RECEIVED → VALIDATED → ROUTED   (sync, ~950ns)
  ── async: volta auth check (~200μs) ──
engine.resume()       → AUTH_CHECKED                      (sync, ~300ns)
  ── async: backend forward (~1-50ms) ──
engine.resume()       → FORWARDED → COMPLETED            (sync, ~300ns)
```

**SM 全体: ~2.2μs (v1.16)**。proxy overhead ~400μs の約 0.5%。SM は判断だけ、I/O は外。この分離が tramli の設計思想と完全に合致する。

## Upgrade Experience: 0.1.0 → 1.16.0

### 良かった点

1. **後方互換性が完璧。** コード変更ゼロで 0.1 → 1.16 のコンパイルが通った。22 バージョンのリリースで API を壊さなかったのは impressive。
2. **`requires!` マクロが便利。** `vec![TypeId::of::<RequestData>()]` → `requires!(RequestData)` — 全プロセッサ/ガードで使える。ボイラープレートが半分になった。
3. **`strict_mode` が安心感を与える。** プロセッサが `produces()` に宣言した型を実際に put しているかを runtime で検証。開発中のバグを早期発見できる。

### 改善要望

1. **`requires!` が `produces()` にも使えるが名前が紛らわしい。** `requires!(BackendResponse)` を produces に使うのは意味的に奇妙。`type_ids!(BackendResponse)` や `data_types!(BackendResponse)` の方が汎用的。
2. **strict_mode のオーバーヘッドが不明。** v0.1: start_flow 707ns → v1.16: 952ns。strict_mode が原因か、他の内部変更か判別できない。`strict_mode: false` のベンチも欲しい。
3. **DataFlowGraph の活用方法が分からない。** ドキュメントが薄い。volta-gateway のフロー定義から `DataFlowGraph` を生成して何が分かるのか、具体例があると嬉しい。
4. **SubFlow の実用例がない。** 将来 plugin を SM のサブフローとして組み込みたいが、SubFlow の使い方が README からは分からない。例: 「認証フローをサブフローとして埋め込む」等。
5. **per-request FlowEngine の alloc/dealloc コスト。** volta-gateway はリクエストごとに `FlowEngine::new(InMemoryFlowStore::new())` している。100K+ req/sec で GC 不要の Rust でもアロケータ負荷が気になる。FlowEngine の reuse パターン (pool) のガイダンスが欲しい。

## Benchmark

| Version | start_flow | full lifecycle |
|---------|-----------|----------------|
| 0.1.0 | 707 ns | 1.69 μs |
| 1.16.0 | 952 ns | 2.23 μs |
| diff | +35% | +32% |

+32% の regression は、strict_mode や内部バリデーション強化の影響と推測。実用上は proxy overhead (~400μs) の 0.5% なので無視できる。ただし、100K req/sec × 2.2μs = 220ms/sec の CPU 消費は累積で見ると気になる。

## Feature Wishlist

1. **FlowEngine pool** — `FlowEngine::reset()` で state をクリアして再利用。alloc 削減。
2. **`DataFlowGraph::to_mermaid()`** — フロー定義から Mermaid データフロー図を自動生成して README に埋め込みたい。
3. **SubFlow の例** — 認証フロー → メインフロー の composition。
4. **`FlowContext::snapshot()`** — デバッグ用に context の全型を JSON dump。
5. **`Builder::on_state_enter(S, callback)`** — 状態遷移フックで metrics / logging を SM 内で完結させたい。

## Conclusion

tramli は volta-gateway の「心臓」として 2 日間・64 テスト・3,658 行の実戦を生き延びた。B-pattern (sync SM + async I/O) の分離が、proxy のレイテンシを SM に汚染させない設計を可能にしている。

v1.16 の `requires!` と `strict_mode` は即座に採用した。DataFlowGraph と SubFlow は将来活用したいが、ドキュメントの充実を待っている。

**最も重要な改善要望: FlowEngine の reuse (pool) パターン。** per-request alloc が高負荷で bottleneck になる可能性がある。
