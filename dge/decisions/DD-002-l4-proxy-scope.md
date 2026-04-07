# DD-002: L4 proxy は認証対象外・IP 制限で保護

**Date:** 2026-04-07
**Status:** Accepted
**Session:** [v6](../sessions/2026-04-07-gateway-tribunal-v6.md), [v7](../sessions/2026-04-07-gateway-tribunal-v7.md), [v8](../sessions/2026-04-07-gateway-tribunal-v8.md)

## Decision
L4 (TCP/UDP) proxy は volta auth の認証対象外とする。
IP allowlist で保護する仕組みを追加し、ドキュメントで明記する。

## Rationale
- L4 は HTTP レイヤーではない。TCP ポートフォワーディングに HTTP 認証は意味がない (ヤン v6)
- ただし無制限公開は危険。IP 制限は必須 (Red Team v6)
- 「認証特化 proxy に認証なしの L4」はアーキテクチャ矛盾 (ハウス v6) → ドキュメントで明確にする
- 将来的に L4 を別バイナリに分離する選択肢は保持する (ソクラテス v8)

## Alternatives considered
- L4 proxy を削除 → ユースケース (DB ポートフォワーディング等) が消える
- L4 に独自認証を追加 → over-engineering
