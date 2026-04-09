# volta-gateway Backlog

> Last updated: 2026-04-09

## Completed (Day 1-3)

<details>
<summary>~90 items completed (click to expand)</summary>

Phase 5 (4), Layer 3 (5), tribunal fixes (7), v0.2.0 (7), v0.3.0 bench (7),
code review (4), v0.5.0 PROD (5), GitHub issues #1-28 (28), #33-38 (5),
#40-41 (2), Cargo workspace (1), tramli 3.6.1 upgrade, auth-core Phase 0.

**Tests: 90** (gateway 80 + auth-core 10)
**Features: 30+**
**Crates: 3** (gateway, auth-core, volta-bin)
</details>

## auth-core Roadmap (DD-005)

| Phase | Item | Status | Description |
|-------|------|--------|-------------|
| **0** | **JWT verify in-process** | **✅ Done** | auth-core crate + gateway 統合。250µs → ~1µs |
| 1 | Session store + policy engine | 📋 Next | SessionStore trait, PolicyEngine (role/tenant check) |
| 1.5 | Token refresh + revocation | 📋 | refresh token rotation, revocation list |
| 2 | OIDC flow (tramli SM) | 📋 | OidcFlowDef → Rust tramli。Google/GitHub/Microsoft IdP |
| 2.5 | MFA flow (tramli SM) | 📋 | TOTP + email code。MfaFlowDef → Rust |
| 3 | Passkey flow (tramli SM) | 📋 | WebAuthn registration + authentication |
| 3.5 | Invite flow | 📋 | Email invite → accept → join tenant |
| 4 | SAML | 📋 | DD-005: Rust (samael) or Java sidecar 判断 |
| 5 | volta single binary | 📋 | volta-bin = gateway + auth-core in-process |

### Phase 1 詳細 (Next)

```
auth-core/src/
  jwt.rs         ✅ Done — JwtVerifier (HS256/RS256)
  session.rs     ✅ Done — SessionVerifier (cookie → JWT → headers)
  store.rs       📋 — SessionStore trait (in-memory + SqlFlowStore via tramli FlowStore trait)
  policy.rs      📋 — PolicyEngine (role check, tenant isolation, IP restrict)
  token.rs       📋 — Token refresh, rotation, revocation
  config.rs      📋 — AuthCoreConfig (from volta-auth-proxy's VoltaConfig)
```

### Phase 2 詳細

```
auth-core/src/flow/
  oidc/
    state.rs     📋 — OidcFlowState enum (tramli FlowState)
    def.rs       📋 — OidcFlowDef (Builder, 1:1 from Java)
    processors/  📋 — OidcInitProcessor, TokenExchangeProcessor, etc.
  mfa/
    state.rs     📋 — MfaFlowState
    def.rs       📋 — MfaFlowDef
  passkey/
    state.rs     📋 — PasskeyFlowState
    def.rs       📋 — PasskeyFlowDef
```

## Open — GitHub Issues

| # | Issue | Category | Priority |
|---|-------|----------|----------|
| #37 | Streaming compression (async-compression) | 機能 | 🟡 Medium |
| #39 | Access log file separation (tracing-appender) | 運用 | 🟡 Medium |
| #42 | traefik-to-volta config converter (STR-10) | ツール | 🔴 Critical |
| #43 | ACME DNS-01 + zero-config HTTPS (STR-2/3) | 機能 | 🟠 High |
| #44 | Docker labels source — full Docker API (STR-4) | 機能 | 🟠 High |
| #45 | Getting Started guide (STR-7) | DX | 🟠 High |
| #46 | README messaging rewrite (STR-6) | マーケ | 🟠 High |
| #47 | Traefik vs volta benchmark article (STR-11) | マーケ | 🟠 High |

## Open — Technical Debt

| # | Item | Severity |
|---|------|----------|
| CR-10 | HTTPS backend (mTLS module ready) | 🟡 Medium |
| GW-39 | proxy.rs 分割 (1,100行超) | 🟡 Medium |
| GW-41 | L4 proxy IP 制限 | 🟡 Medium |
| PROD-6 | Chunked body Limited | 🟡 Medium |

## Open — Strategic

| # | Item | Phase | Priority |
|---|------|-------|----------|
| MIG-3 | 並行運用戦略 (Rust read + Java write) | DD-005 Ph1 | 🟠 High |
| STR-5 | docker-compose → services.json 自動生成 | DD-004 | 🟡 Medium |
| STR-8 | Caddy 差別化 (エコシステム訴求) | DD-004 | 🟡 Medium |
| STR-9 | volta-console 統合デモ | DD-004 | 🟡 Medium |
| MIG-2 | SAML: Rust or Java sidecar 判断 | DD-005 Ph4 | 🟡 Medium |
| MIG-4 | volta single binary vision | DD-005 Ph5 | 🟢 Low |
| Wasm | Plugin system Wasm runtime | — | 🟢 Low |

## Design Decisions

- [DD-001](../dge/decisions/DD-001-cors-default-deny.md) — CORS デフォルトを deny に変更
- [DD-002](../dge/decisions/DD-002-l4-proxy-scope.md) — L4 proxy は認証対象外
- [DD-003](../dge/decisions/DD-003-accept-criteria.md) — v0.1.0 Accept 基準
- [DD-004](../dge/decisions/DD-004-traefik-user-acquisition.md) — Traefik ユーザー獲得戦略
- [DD-005](../dge/decisions/DD-005-java-to-rust-migration.md) — volta-auth-proxy Java→Rust 段階的移行
- [DD-006](../dge/decisions/DD-006-auth-proxy-rs-repo.md) — auth-proxy-rs は Cargo workspace で gateway と同居
