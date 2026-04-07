# DD-001: CORS デフォルトを「ヘッダなし」に変更

**Date:** 2026-04-07
**Status:** Accepted
**Session:** [v7](../sessions/2026-04-07-gateway-tribunal-v7.md), [v8](../sessions/2026-04-07-gateway-tribunal-v8.md)

## Decision
cors_origins 未設定時のデフォルトを wildcard `*` から「CORS ヘッダなし」に変更する。
明示的に `cors_origins: ["*"]` を設定した場合のみ wildcard を返す。

## Rationale
- 認証特化 proxy で暗黙のオープン CORS はセキュリティ上矛盾する (千石 v7)
- セキュリティ意識の高い開発者は「設定していないのに CORS が通る」と混乱する
- v0.1.0 なのでセマンティック破壊の影響なし

## Alternatives considered
- wildcard のまま + ドキュメントで注意喚起 → セキュリティデフォルトとして不適切
