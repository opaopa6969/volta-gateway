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
- **Risk-based login wiring** — Phase 4c. The risk engine is now live on the OIDC
  callback: a long-lived `__volta_kd` device marker (hash remembered per user in
  `risk_known_devices`, migration 030) flags **new devices**, and the source IP
  is compared to the user's most recent session (**ip_changed**). `complete_oidc`
  runs `risk::evaluate`; a `Block` decision refuses the login (403 `LOGIN_BLOCKED`
  + audit event) while normal logins now record IP/User-Agent on the session.
  **Fail-open**: any store/lookup error resolves to allow, so the change is safe
  to deploy even before the migration runs. New `RiskDeviceStore` +
  device-cookie helpers. **Phase 4c** of `docs/auth-methods-landscape.md`.
- **Risk engine + passkey AAGUID metadata** — Phase 4 (a+b). `auth-core::risk`
  scores login signals (new device, IP/ASN/geo change, impossible travel,
  off-hours, UA change) into a level and maps it against tenant thresholds
  (default action 4 / block 5, matching the Java `RiskCheckProcessor`) to
  Allow/StepUp/Block — **fail-open** (no signals → safe). `auth-server::aaguid`
  maps FIDO MDS AAGUIDs to model names, and `GET /api/v1/users/{id}/passkeys`
  now returns an `authenticator` label (iCloud Keychain / YubiKey 5 NFC /
  Windows Hello / …) instead of an opaque id. Wiring the engine into the login
  callback (known-device cookie, IP/geo comparison, step-up/block enforcement)
  is the next slice (4c). **Phase 4** of `docs/auth-methods-landscape.md`.
- **OpenID Provider endpoints** — Phase 3b. volta is now an authorization server /
  IdP for downstream apps: `/.well-known/openid-configuration` (discovery),
  `GET /authorize` (authorization_code + **mandatory PKCE S256** + consent screen
  with remembered consent), `POST /authorize/consent`, `POST /oauth/token` for
  the `authorization_code` and `refresh_token` grants (**refresh rotation with
  reuse detection → whole-family revocation**), `GET /userinfo`,
  `POST /oauth/introspect` (RFC 7662), `POST /oauth/revoke` (RFC 7009),
  `GET /end_session` (RP-initiated logout), and admin client registration
  (`POST/GET /api/v1/oauth/clients`). id_tokens are RS256 (iss/aud/nonce/email),
  verifiable via JWKS. New tables `oauth_clients`, `oauth_authorization_codes`,
  `oauth_refresh_tokens`, `oauth_consents` (migration 029); secrets/codes/tokens
  stored as hashes. New `handlers/op.rs` + `auth-core` oauth records/stores +
  `JwtIssuer::sign` (arbitrary claims) + `crypto::sha256_base64url` (PKCE).
  Verified end-to-end against Postgres. **Phase 3b** of
  `docs/auth-methods-landscape.md`.
- **OpenID Provider signing foundation (RS256 + real JWKS)** — Phase 3a. On boot
  the server ensures an OP RSA signing key exists (`op_keys::bootstrap_op_issuer`,
  idempotent — reuses the persisted key across restarts) and
  `GET /.well-known/jwks.json` now publishes the real public key as a JWK
  (`kty/alg/use/kid/n/e`) instead of an empty array. `JwtIssuer` gained a
  `kid`-stamping RS256 constructor (`new_rsa_with_kid`); the OP issuer is wired
  into `AppState.op_issuer` for the upcoming OP token endpoints. The internal
  session JWT stays HS256 (gateway shared-secret contract unchanged) — the OP
  uses a separate asymmetric key. `POST /api/v1/admin/keys/rotate` now generates
  real RSA keypairs (was an HS256 placeholder). Verified end-to-end against
  Postgres. **Phase 3a** of `docs/auth-methods-landscape.md`.
- **Multi-account sessions + account chooser** (Google-style "signed in on this
  browser"). New `__volta_accounts` cookie remembers every session id; `GET
  /accounts` renders the chooser (active badge / switch / add / per-account &
  all sign-out), `POST /accounts/{use,signout,signout-all}` act on it, and
  `GET /login?add=1` adds another account by forcing the upstream IdP chooser
  (`prompt=select_account`). Implemented via **lazy reconciliation** — the 8
  login-completion sites are untouched; the active session is folded into the
  list on `/accounts` and the outgoing active is stashed on `/login?add=1`.
  New `handlers/accounts.rs`, `idp::authorization_url_pkce_prompt`, cookie
  helpers in `helpers.rs`. **Phase 2** of `docs/auth-methods-landscape.md`.
- **OAuth 2.0 Device Authorization Grant (RFC 8628)** — cross-device / QR sign-in
  for input-constrained & native clients (CLI/TV/desktop). New endpoints
  `POST /oauth/device_authorization`, `GET /device` (approval UI),
  `POST /device/{approve,deny}`, and a `device_code` grant on `POST /oauth/token`
  (with `authorization_pending` / `slow_down` / `access_denied` / `expired_token`
  polling responses). `device_code` stored as SHA-256 hash, short-lived
  `user_code`, `slow_down` interval enforcement. New `auth-core` `flow/device_grant.rs`
  + `store/device_grant.rs` + `record/device_grant.rs`, migration
  `028_create_device_authorization_grants.sql`, and PG integration tests.
  Designed as **Phase 1** of `docs/auth-methods-landscape.md`.
- `docs/auth-methods-landscape.md` — comprehensive map of real-world auth methods,
  current volta coverage matrix, prioritised gap analysis, and implementation
  roadmap (RP/passwordless done; OP / multi-account chooser / device-grant / risk
  the main gaps).
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
- **Production cutover (2026-06-27)**: `auth.unlaxer.org` backend switched from
  Java `volta-auth-proxy` (:7070) to Rust `auth-server` (:7072) via a
  fresh-schema DB migration (`volta_auth_rs`). Java retained as a no-loss
  rollback standby. See `docs/java-to-rust-migration-runbook.md`.
- Google-style passkey UX (`docs/passkey-ux-design.md`): `/login` shows a
  Google + passkey choice page with **Conditional UI** (autofill, mediation
  `conditional`); `/` is now an **account page** (passkey list / add / delete /
  sign out) with a post-login **auto-enrollment** prompt; WebAuthn/server errors
  are translated to next-action guidance.
- `/viz` passkey flow enriched to mirror the real runtime: registration
  (attestation) + discoverable authentication ceremonies, sign-counter clone
  check, and error terminals (was: happy-path assertion only).

### Changed
- README.md / README-ja.md rewritten to tramli-quality standard: Rust+Java
  dual implementation, 96 routes, `tramli = "3.8"` dependency, TOC.
- Rate limits raised so page-load-triggered flows don't lock out legitimate
  users: OIDC 10→30/min/IP, passkey 5→30/min/IP.

### Fixed
- Cutover regressions: `GET /` returned 404 (Java redirected to `/login`) → now
  a session-aware landing; an authenticated user landing on `/` looped back
  through the IdP.
- MFA lockout: a fresh OIDC session always had `mfa_verified_at = None` and
  `/auth/verify` forced `/mfa/challenge` unconditionally — users with no enrolled
  MFA had no code to enter. Now gated on `MfaStore::has_active`.
- Passkey persistence used bincode, which can't round-trip webauthn-rs types
  (`deserialize_any`): challenge state **and** credentials moved to `serde_json`.
- Passkey `signCount = 0` authenticators (Windows Hello / synced passkeys) were
  rejected as clones; the counter check now only applies when count > 0.

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
