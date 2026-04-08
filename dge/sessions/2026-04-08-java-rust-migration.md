# DGE 座談会: volta-auth-proxy Java→Rust 移植判断

> Date: 2026-04-08
> Structure: 🗣 座談会
> Characters: ☕ ヤン / 👤 今泉 / ⚔ リヴァイ / 🎭 ソクラテス / 🦈 大和田

## 現状
- Java 9,348行、87ファイル
- SM フロー4つ (OIDC, MFA, Passkey, Invite) — tramli Java で構成
- IdP 5つ (Google, GitHub, Microsoft, LinkedIn, Apple)
- SAML, SCIM, FraudAlert, GDPR, Audit, DeviceTrust

## Key Insights

1. **GC は問題ない。移行動機はマーケティングと運用統合**
2. **Phase 0 (JWT verify in-process) だけで認証レイテンシ 0.25ms → ~1μs**
3. **tramli が 1:1 対応するので SM フロー移植は機械的**
4. **SAML は移植しない選択肢がある (Java sidecar)**
5. **最終形: volta single binary (gateway + auth + console)**

## Gaps

| # | Gap | Severity | Phase |
|---|-----|----------|-------|
| MIG-1 | JWT verify in-process | High | 0 |
| MIG-2 | SAML 判断 (Rust or Java sidecar) | Medium | 3 |
| MIG-3 | 並行運用戦略 | High | 1-2 |
| MIG-4 | single binary vision | Medium | 4 |

## Decision
DD-005 として記録。Phase 0 から開始。
