# DGE 査読劇 v7: volta-gateway — 前提・品質・矛盾

> Date: 2026-04-07
> Structure: ⚖ 査読劇 (tribunal) — Round 7
> Evaluators: 👤 今泉 / 🎩 千石 / 🕵 右京
> Subject: volta-gateway v0.1.0 — GW-36 修正後 (24 テスト PASS)

## Verdicts

| Reviewer | Verdict |
|----------|---------|
| 👤 今泉 | **Minor Revision** — ACME/L4 は誰のため？ config 複雑化 |
| 🎩 千石 | **Minor Revision** — CORS デフォルト wildcard、circuit open UX |
| 🕵 右京 | **Minor Revision** — Host 正規化不整合、dead code 16件 |

## Gaps (5 new)

| # | Gap | Category | Severity |
|---|-----|----------|----------|
| GW-43 | minimal config サンプルなし | DX | Medium |
| GW-44 | CORS デフォルトが wildcard — ヘッダなしに変更すべき | セキュリティ | Medium |
| GW-45 | Host 正規化の不整合 (config/proxy/websocket/redirect) | バグ | Medium |
| GW-46 | circuit open 時に Retry-After なし | UX | Low |
| GW-47 | 16 dead code warnings | 品質 | Low |

## Key Insight

**3ラウンド (v5-v7) で指摘の severity が確実に下がった。**
v5: 4 High, 0 Critical
v6: 1 Critical, 2 High → Critical 修正済
v7: 0 Critical, 0 High, 3 Medium, 2 Low

**今泉の問い「ACME と L4 は誰のため？」は設計判断として記録に値する。**
