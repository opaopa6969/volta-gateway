# DD-003: v0.1.0 リリース Accept 基準

**Date:** 2026-04-07
**Status:** Accepted
**Session:** [v8](../sessions/2026-04-07-gateway-tribunal-v8.md)

## Decision
v0.1.0 リリースの Accept 基準を以下とする:
1. Critical Gap ゼロ
2. セキュリティ上のデフォルトが安全側 (CORS deny, fail-closed auth)
3. Host 正規化の一貫性 (ルーティング失敗バグなし)
4. WebSocket 接続数に上限あり (リソース枯渇防止)
5. 24+ テスト PASS

v0.2.0 で追加: ベンチマーク基盤、metrics 拡充、config ドキュメント、テストカバレッジ拡大。

## Rationale
- 舞台監督 v8: 「合格基準が定義されていないので査読が収束しない」
- 4ラウンド 23 Gap のうち、ブロッカーを 5 件に絞る判断が必要
- 「完璧」ではなく「安全なデフォルト + 既知の問題を文書化」でリリース

## Alternatives considered
- ベンチマークをブロッカーに含める → リリースが遅延。v0.2.0 で十分
- 全 Gap 解消をブロッカーに → 永遠にリリースできない (舞台監督の指摘)
