# DGE 査読劇 v9: volta-gateway 論文査読 — 競合分析と主張の妥当性

> Date: 2026-04-07
> Structure: ⚖ 査読劇 (tribunal) — Round 9 (Paper Review)
> Evaluators: 🧩 マンガー / 📊 ビーン / 🏥 ハウス
> Subject: "volta-gateway: State-Machine-Driven Auth-Aware Reverse Proxy for Small-Scale SaaS"

## Verdicts

| Reviewer | Verdict |
|----------|---------|
| 🧩 マンガー | **Minor Revision** — scope 明示 + 代替アーキテクチャ比較 |
| 📊 ビーン | **Major Revision** — E2E ベンチマークなしの性能主張は不誠実 |
| 🏥 ハウス | **Major Revision** — 動機の誠実性、integration test、実ユーザー不在 |

## Key Insights

1. **「5-10 倍高速」の主張に E2E 実証データがない (GW-50)**
   - volta-gateway の 0.5-1ms は localhost RTT のみ (auth ロジック含まず)
   - Traefik も localhost auth なら 1-2ms の可能性
   - 同条件比較なしの性能主張は不誠実

2. **論文の動機が post-hoc rationalization (GW-55)**
   - 本当の動機: Traefik + volta-auth-proxy の設定が面倒
   - 論文の動機: 認証レイテンシ問題の解決
   - 正直な動機の方が読者の信頼を得る

3. **Integration test がゼロ (GW-53)**
   - 30 テストは全て単体テスト
   - 実 HTTP リクエスト → proxy → backend のテストなし

## Gaps (6 new)

| # | Gap | Category | Severity |
|---|-----|----------|----------|
| GW-50 | E2E ベンチマーク (req/sec, p99) なし | 論文 | Critical |
| GW-51 | 論文 scope が暗黙的 | 論文 | Medium |
| GW-52 | Traefik + localhost auth 同条件比較なし | 論文 | High |
| GW-53 | Integration test ゼロ | 品質 | High |
| GW-54 | SM 遷移ログ活用事例なし | 論文 | Low |
| GW-55 | 論文の動機が post-hoc rationalization | 論文 | Medium |
