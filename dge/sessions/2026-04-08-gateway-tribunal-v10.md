# DGE 査読劇 v10: volta-gateway — 新機能集中査読

> Date: 2026-04-08
> Structure: ⚖ 査読劇 (tribunal) — Round 10
> Evaluators: ⚔ リヴァイ / 😈 Red Team / 🕵 右京
> Subject: v9 以降の新機能集中査読

## Verdicts

| Reviewer | Verdict |
|----------|---------|
| ⚔ リヴァイ | **Major Revision** — cache/mTLS 未統合、traceparent 壊れ、proxy.rs 1095行 |
| 😈 Red Team | **Minor Revision** — admin API localhost only で基本安全。mirror ヘッダ漏洩 |
| 🕵 右京 | **Major Revision** — cache/mTLS config 受付るが動かない。path_prefix 壊れ |

## Gaps (6) → 全修正済み

| # | Gap | Severity | Status |
|---|-----|----------|--------|
| GW-56 | cache 未統合 | Critical | ✅ proxy.rs に lookup/store 統合 |
| GW-57 | mTLS 未統合 | Critical | ⚠️ モジュール ready, per-route client 選択は次 |
| GW-58 | traceparent span_id = 0 | High | ✅ UUID lower 64 bits |
| GW-59 | path_prefix 同一 host で壊れる | High | ✅ validation 警告追加 |
| GW-60 | plugin で volta_headers アクセス不可 | High | ✅ context に merge |
| GW-61 | mirror に X-Volta-* 漏洩 | Medium | ✅ strip 追加 |

## Key Insight

**速度を優先してモジュール作成と proxy.rs 統合を分離したことが、
issue close 後の「動かない」バグを生んだ。**
モジュール + テスト + 統合 + E2E 検証をセットにすべき。
