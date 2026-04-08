# DD-005: volta-auth-proxy Java→Rust 段階的移行

**Date:** 2026-04-08
**Status:** Accepted
**Session:** [DGE座談会](../sessions/2026-04-08-java-rust-migration.md)

## Decision

volta-auth-proxy (Java 9,348行) を段階的に Rust に移行する。全書き直しではなく、Phase 0-4 の段階的アプローチ。

## Migration Phases

```
Phase 0: Auth verify in-process (JWT check in gateway)     — 1-2日
Phase 1: volta-auth-core Rust crate (session, JWT, policy)  — 2-3週
Phase 2: SM フロー移植 (OIDC, MFA, Passkey, Invite)          — 3-4週
Phase 3: IdP + SAML + SCIM                                    — 4-6週
Phase 4: Java deprecate + single binary                       — 1週
```

## Key Principles

1. **Read path first** — verify (読み取り) を先に Rust 化、write path (ログインフロー) は Java に残す
2. **SAML は最後** — Java OpenSAML は 15年のバトルテスト。Rust samael は若い。Java sidecar で残す選択肢あり
3. **tramli 統一** — Java tramli と Rust tramli の SM 定義が 1:1 対応。FlowState enum + Processor の移植は機械的
4. **shadow mode** — Java 版と Rust 版を並行運用し、結果を比較検証してから切り替え

## Rationale

- 性能: Java のGCは実用上問題ない。移行の動機は性能ではなくマーケティングと運用
- マーケティング: "Full Rust stack" の訴求力。2つのランタイム (JVM + Rust) は運用負荷
- 最終形: volta single binary (gateway + auth + console) — Caddy と同等の UX
- リスク: SAML 移植は事故る可能性が高い。Phase 3 で判断

## Alternatives

- 全書き直し (Big Bang) → 2-3ヶ月、並行メンテなし、リスク高
- 移行しない → マーケティング上の弱点が残る、2バイナリ運用
- Go で書き直す → エコシステム統一にならない
