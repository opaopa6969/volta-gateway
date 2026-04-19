[日本語版はこちら / Japanese](CHANGELOG.md#日本語)

# Changelog

All notable changes to **volta-gateway** are documented here. The repository is
a Cargo workspace with five crates:
`gateway`, `auth-core`, `auth-server`, `volta-bin`, and `tools/traefik-to-volta`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **tramli line:** every release pins a concrete `tramli` major version. See
> [`docs/architecture.md`](docs/architecture.md) for why the state machine sits
> at the core of every crate in the workspace.

---

## [Unreleased]

### Added
- `CHANGELOG.md` (this file).
- `docs/architecture.md` / `-ja.md` — FlowEngine, routing, auth-server 5-merge
  router structure, plugin system, rate limiting.
- `docs/parity.md` / `-ja.md` — Rust vs Java feature parity table covering the
  full **96-route** auth-server surface.
- `docs/getting-started.md` (English) + `-ja.md` (Japanese split) — local
  bring-up with `mock_auth` / `mock_backend`, load testing, and unified-binary
  flow.
- `docs/feedback.md` — captures the `tramli_react` / tramli feedback cycle
  (see v3.2.0 → v3.8.0 timeline below).

### Changed
- README.md / README-ja.md rewritten to tramli-quality standard: Rust+Java
  dual implementation, 96 routes, `tramli = "3.8"` dependency, TOC.

---

## [0.3.0] — 2026-04-17 — "Final burst"

**Highlights:** auth-server hardened, tramli 3.8 upgrade, SAML XML-DSig,
flow definition validation, audit DB wiring.

### Added
- **auth-server** (`0ccf18f`): SAML XML-DSig verification path,
  `FlowDefinition` validation helpers, audit DB insert wiring.
- **auth-server** (`0903e3f`): burst backlog — SAML defences (XXE, DOCTYPE
  reject), M2M client flow, OIDC ID-token validation, admin pagination
  (`page / size / sort / q`), tramli-viz endpoints (`/viz/flows`,
  `/viz/auth/stream`), Redis SSE bridge, passkey hardening.
- **auth-core** + **auth-server** (`7922046`): PKCE (`code_verifier` /
  `code_challenge`) plus `KeyCipher` (AES-GCM + PBKDF2) for encrypting PKCE
  verifiers at rest — closes backlog P0 #1 and Java issues #4 / #15 / #16.
- `auth-server/docs/specs/` — 8 spec documents (audit insert, bearer M2M
  scope, flow-definition validation, Mermaid, OIDC ID-token, passkey/WebAuthn,
  Redis SSE, SAML signature).

### Changed
- **tramli** pinned to `3.8` across the workspace (gateway, auth-core).
  `tramli-plugins` at `3.6.1`.
- Auth event bus now fans out via Redis pub/sub (`auth_events::AuthEventBus`).
- Admin endpoints: 5 handlers now accept `PageRequest` (users, sessions,
  audit, members, invitations); DB gets `migrations/021_pagination_indexes.sql`.

### Security
- **P0 suite** (Java upstream `abca91e`, 20 issues): webhook SSRF guard,
  `/auth/*` per-endpoint rate limits (oidc 10/min, mfa 5/min, passkey 5/min,
  invite 20/min, magic-link 5/min), SAML devMode localhost-only gate, admin
  OAuth scope enforcement, session-cookie flag hardening, Unicode NFC email
  normalization, passkey counter atomic update, XXE rejection in SAML parser,
  constant-time secret compare via `subtle`.
- **18 / 21** P0 items closed; 3 deferred (`KeyCipher` PKCE fallback — now
  shipped in this release).

---

## [0.2.1] — 2026-04-14 — "Sync-from-Java"

### Added
- **auth-server** (`e16cd4a`): Rust port of Java upstream commits through
  `afb6eab` (2026-04-13). Implements AUTH-010 unified verify flow,
  `/mfa/challenge` page, auth event SSE stream (`/viz/auth/stream`),
  `local_bypass::LocalNetworkBypass` for ForwardAuth, and the paginated
  admin endpoints listed above.
- `auth-server/docs/sync-from-java-2026-04-14.md` — traceable mapping from
  every adopted Java commit to its Rust landing spot.

### Fixed
- `sanitize_redirect` now allows `auth_public_url` suffix matches — fixes
  `ERR_TOO_MANY_REDIRECTS` on callback (`ad2a0a1`).
- ForwardAuth now forwards the real client IP via `X-Real-IP` (`1054450`).

---

## [0.2.0] — 2026-04-12 — "Monetizer + Mesh"

### Added
- **gateway** (`fa44131`, `7d6b382`): `builtin::Monetizer` plugin — injects
  `X-Monetizer-Plan / -Status / -Features / -Show-Ads / -Trial-End` headers
  from a billing backend, with an LRU safety valve (DD-016).
- **gateway** (`b2174ec`): mesh VPN integration — Headscale sidecar routing
  + `docs/MESH-VPN-SPEC.md`.
- **gateway** (`b62498d`): streaming compression (#37), access-log file
  separation (#39), config schema v3 (#55).

### Security
- **gateway** (`90f195c`): 7 security issues closed (#48–#54) — path
  traversal, header injection, response-header forgery mitigations.

---

## [0.1.0] — 2026-04-10 — "96 routes"

**The line-in-the-sand release.** Java-parity reached for auth-server.

### Added
- **auth-server** (`e4a2daf`): new crate — 96 Axum routes matching Java
  `volta-auth-proxy` 1:1 (OIDC, SAML, MFA, Passkey, Invite, Magic Link,
  Webhook, Audit, SCIM 2.0, Billing, Policy, GDPR, Admin HTML stubs,
  JWKS, healthz). Router composition: core router plus 5 rate-limited
  `route_layer` sub-routers merged via `Router::merge` — the **5-merge
  structure** documented in [`docs/architecture.md`](docs/architecture.md).
- **auth-core** (`d0a7ee6`): `SqlStore`, `AuthService`, `PgStore`,
  `FlowPersistence`, WebAuthn (`webauthn-rs`), MFA (TOTP), Magic Link,
  Signing Keys with DB persistence. 23 SQL migrations.
- **gateway** (`5066bbf`): Docker labels config source (bollard), ACME
  DNS-01 (instant-acme + Cloudflare), config hot reload, E2E tests.
- `docs/getting-started.md`, `docs/benchmark-article.md`,
  `docs/migration-from-traefik.md` (en+ja).
- **tools/traefik-to-volta** (`fffc796`): converter CLI.
- **volta-bin** (`ed1a0f2`): unified binary — gateway + auth-core
  in-process (DD-005 Phase 5).

### Changed
- Workspace restructure (`db06a57`): flat `src/` split into four crates
  (gateway, auth-core, volta-bin, tools). See DD-006.
- tramli upgrade trail in the run-up to 0.1.0:
  `3.2` (`c847c2a`) → `3.3` (`0e9f4e8`) → `3.4` (`bf7f5c0`) →
  `3.5` (`f8e594f`) → `3.6` (`ad16aa1`) → `3.6.1` (`b7fef15`,
  `NoopTelemetrySink` benchmark baseline).

---

## Earlier history

Phase-0 / Phase-1 / Phase-2 work (pre-workspace, single-crate `volta-gateway`)
is summarized in [`docs/HANDOFF.md`](docs/HANDOFF.md) and
[`docs/backlog.md`](docs/backlog.md). Highlights:

- `3e8bed1` — 11 bug fixes (#18–#28).
- `bc8b507` — auth cache, backpressure, per-route timeout, `--validate`,
  `/admin/stats` (#33–#36, #38).
- `7d43fef` — README features table (30 features, en+ja).
- `d2d6ac5` — DD-005 Phase 0: in-process JWT verify.
- `3458a95` — auth-core Phase 1.5–3.5: all tramli SM flows ported from Java
  (OIDC, MFA, Passkey, Invite).

---

## tramli upgrade timeline

volta-gateway is tramli's largest production consumer and drove several of
its design decisions. See [`docs/feedback.md`](docs/feedback.md) for the full
`tramli_react` loop (field report → upstream fix → redeploy).

| Date       | tramli | volta-gateway commit | What changed upstream                          |
|------------|--------|----------------------|------------------------------------------------|
| 2026-04-07 | 3.2    | `c847c2a`            | Plugin SPI, lint, diagram, observability       |
| 2026-04-07 | 3.3    | `0e9f4e8`            | `durationMicros` in transition logger          |
| 2026-04-07 | 3.4    | `bf7f5c0`            | API smoothing                                   |
| 2026-04-07 | 3.5    | `f8e594f`            | Chain mode + enhanced telemetry                |
| 2026-04-07 | 3.6    | `ad16aa1`            | `FlowStore` trait, `Builder::strict_mode()`    |
| 2026-04-07 | 3.6.1  | `b7fef15`            | `NoopTelemetrySink` — zero-cost baseline       |
| 2026-04-17 | 3.8    | `0ccf18f`            | `GuardOutput::accept_with` + `guard_data!`     |

---

<a id="日本語"></a>

# 変更履歴 (日本語)

全ての主要な変更は [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) 形式で記録。
バージョン体系は [Semantic Versioning](https://semver.org/lang/ja/) に準拠。

日付・コミット SHA・リリース行は英語版と同一。ここでは日本語読者向けに要点だけを
抜粋する。詳細は英語版 (本ファイル上部) 参照。

## [0.3.0] — 2026-04-17 「Final burst」

- auth-server: SAML XML-DSig 検証・FlowDefinition 検証・audit DB 配線 (`0ccf18f`)。
- auth-server: SAML XXE 対策、M2M クライアント、OIDC ID-token 検証、admin pagination、
  tramli-viz 統合 (`/viz/flows`, `/viz/auth/stream`)、Redis SSE 橋、Passkey 強化 (`0903e3f`)。
- PKCE + `KeyCipher` (AES-GCM + PBKDF2) で PKCE verifier を at-rest 暗号化 (`7922046`)。
- **tramli 3.8** へ全 crate を揃える (`tramli-plugins = 3.6.1`)。
- P0 セキュリティ 20 件中 18 件完了、残 3 件も本リリースで解消。

## [0.2.1] — 2026-04-14 「Sync-from-Java」

- Java upstream (`afb6eab` 時点) を Rust 側に反映 (`e16cd4a`)。
- AUTH-010 統一 verify、`/mfa/challenge`、SSE auth stream、`local_bypass`、
  admin pagination を実装。
- `sanitize_redirect` が `auth_public_url` を許容するよう修正 (`ad2a0a1`)。
- ForwardAuth に real client IP を `X-Real-IP` で転送 (`1054450`)。

## [0.2.0] — 2026-04-12 「Monetizer + Mesh」

- `builtin::Monetizer` 課金ヘッダ注入プラグイン + LRU safety valve (DD-016)。
- Headscale sidecar による mesh VPN 統合。
- streaming compression、access log 分離、config schema v3。
- 7 件のセキュリティ修正 (#48–#54)。

## [0.1.0] — 2026-04-10 「96 routes」

- **auth-server** 新設: Java `volta-auth-proxy` と 1:1 互換の Axum 96 ルート (`e4a2daf`)。
  コアルータに 5 つの `route_layer` サブルータを `Router::merge` で合成する
  **5 マージ構造** (詳細は [`docs/architecture.md`](docs/architecture.md))。
- **auth-core**: `SqlStore` / `AuthService` / `PgStore` / `FlowPersistence` /
  WebAuthn / MFA / Magic Link / Signing Keys。23 個の SQL マイグレーション (`d0a7ee6`)。
- gateway: Docker labels、ACME DNS-01 (Cloudflare)、config hot reload、E2E テスト (`5066bbf`)。
- traefik→volta 変換 CLI、volta-bin 統合バイナリ (DD-005 Phase 5)。
- ワークスペース再編 (`db06a57`, DD-006): 単一 crate から 4 crate に分離。
- tramli 3.2 → 3.6.1 までの段階アップグレード。

## これ以前

単一 crate 時代の詳細は [`docs/HANDOFF.md`](docs/HANDOFF.md) と
[`docs/backlog.md`](docs/backlog.md) を参照。

## tramli バージョン変遷

| 日付       | tramli | volta-gateway コミット | 主な変更点                                        |
|------------|--------|------------------------|---------------------------------------------------|
| 2026-04-07 | 3.2    | `c847c2a`              | Plugin SPI、lint、diagram、observability           |
| 2026-04-07 | 3.3    | `0e9f4e8`              | Transition logger に `durationMicros`              |
| 2026-04-07 | 3.4    | `bf7f5c0`              | API smoothing                                      |
| 2026-04-07 | 3.5    | `f8e594f`              | Chain mode + telemetry 強化                        |
| 2026-04-07 | 3.6    | `ad16aa1`              | `FlowStore` trait、`Builder::strict_mode()`        |
| 2026-04-07 | 3.6.1  | `b7fef15`              | `NoopTelemetrySink` ゼロコストベースライン          |
| 2026-04-17 | 3.8    | `0ccf18f`              | `GuardOutput::accept_with` + `guard_data!`         |

tramli_react フィードバックループの詳細は [`docs/feedback.md`](docs/feedback.md) を参照。
