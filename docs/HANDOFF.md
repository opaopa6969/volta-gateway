# Session Handoff: volta-gateway + auth-core

> From: 2026-04-07〜09 セッション
> To: 次回セッション

## 現状

### Workspace: 4 crates, テスト: auth-core 55 (46 unit + 9 integration), gateway 8 integration

```
volta-gateway/
  Cargo.toml              workspace root
  gateway/                HTTP reverse proxy (30+ features)
  auth-core/              Auth library (5 tramli SM flows)
  volta-bin/              Unified binary (gateway + auth in-process)
  tools/traefik-to-volta/ Config converter CLI
```

### Bench: 6.6x faster than Traefik (p50)

## 今回完了した全作業

### auth-core

| # | タスク | 詳細 |
|---|--------|------|
| 1 | SqlStore DAO traits + PostgreSQL | 7 record types, 6 store traits, PgStore (sqlx), 7 SQL migrations |
| 2 | Processor DB 配線 | JwtIssuer + AuthService (OIDC/MFA/Token/Invite orchestrator) |
| 3 | Integration test | testcontainers + PostgreSQL, 9 tests (全 Store + FlowPersistence) |
| 4 | FlowPersistence | auth_flows/transitions テーブル, optimistic lock |
| 5 | WebAuthn/Passkey | PasskeyService (webauthn-rs 0.6, `webauthn` feature) |

### gateway

| # | タスク | 詳細 |
|---|--------|------|
| 6 | Docker labels config source | bollard で Docker API 接続、コンテナ自動検出 + events watch |
| 7 | Config source hot reload 統合 | watch() → ArcSwap merge (static + dynamic routes) |
| 8 | ACME DNS-01 Phase 1+2 | TlsConfig 拡張 + Cloudflare provider + instant-acme 完全フロー |
| 9 | SAML sidecar routing | DD-005 準拠、config 例追加 |
| 10 | E2E テスト追加 | public route, unknown host, auth bypass (計 8 tests) |

### docs

| # | タスク | 詳細 |
|---|--------|------|
| 11 | Benchmark 記事 | docs/benchmark-article.md |
| 12 | Getting Started ガイド | docs/getting-started.md |
| 13 | README 更新 | EN/JA 両方、workspace 構成反映 |

## テスト結果

| crate | テスト | 結果 |
|-------|--------|------|
| auth-core unit | 46 | all pass |
| auth-core integration (testcontainers) | 9 | all pass |
| gateway integration | 8 | all pass |

## 残タスク

なし。HANDOFF の全項目完了。

次のフェーズ候補:
- SAML Java sidecar 実装 (DD-005 Phase 3)
- SCIM provisioning
- WebAuthn E2E テスト (real authenticator mock)
- cert renewal scheduler (ACME auto-renew)
- Kubernetes ingress controller mode
