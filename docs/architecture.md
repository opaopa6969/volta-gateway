[日本語版はこちら / Japanese](architecture-ja.md)

# volta-gateway Architecture

> Companion doc to the top-level [README](../README.md). This document focuses
> on *how the pieces fit together*: the FlowEngine at the core, the routing
> table, the `auth-server` 5-merge router, the plugin system, and the
> rate-limiting layers.

## 1. Workspace layout

```
volta-gateway/                       Cargo workspace root
├── gateway/          HTTP reverse proxy (96 routes in auth-server → forwarded)
├── auth-core/        Auth library — JWT, session, OIDC/MFA/Passkey SM flows
├── auth-server/      Axum HTTP API — Java volta-auth-proxy 1:1 replacement
├── volta-bin/        Unified binary (gateway + auth-core in-process)
└── tools/
    └── traefik-to-volta/  Config converter CLI
```

Shared dependencies: `tramli = "3.8"` and `tramli-plugins = "3.6.1"` in both
`gateway` and `auth-core`. That pin is not cosmetic — see [§4](#4-tramli-version-policy).

## 2. The FlowEngine at the edge

Every request that enters `gateway` drives **one tramli `FlowInstance`**.
The state machine is declared in `gateway/src/flow.rs`:

```text
         ┌─────────┐   ┌───────────┐   ┌────────┐
[*] ──▶ │Received │──▶│ Validated │──▶│ Routed │──▶ [AuthGuard] ──▶ AuthChecked
         └─────────┘   └───────────┘   └────────┘        │
              │              │             │              ▼
              └── BAD_REQUEST, REDIRECT, DENIED, BAD_GATEWAY, GATEWAY_TIMEOUT
                                                          │
                                                          ▼
                                                   [ForwardGuard] ──▶ Forwarded
                                                                         │
                                                                         ▼
                                                                     Completed [*]
```

Processors (sync, <2µs each):

| Processor           | `requires`        | `produces`      | Purpose                                |
|---------------------|-------------------|-----------------|----------------------------------------|
| `RequestValidator`  | `RequestData`     | —               | header-size / body-size / host / path traversal checks (literal + URL-encoded). |
| `RoutingResolver`   | `RequestData`     | `RouteTarget`   | host → backend lookup, wildcard + round-robin + weighted LB. |
| `CompletionProcessor` | `BackendResponse` | —             | finalise metrics, emit transition log. |

Guards (sync decision, async I/O outside):

| Guard          | on External    | External input        |
|----------------|----------------|-----------------------|
| `AuthGuard`    | Routed → AuthChecked | `AuthData` injected after the async `volta` check |
| `ForwardGuard` | AuthChecked → Forwarded | `BackendResponse` injected after backend call |

### The B-pattern: sync SM + async I/O

```rust
let flow_id = engine.start_flow(&def, &id, initial_data)?; // sync, ~1µs (auto-chains)
let auth    = volta_client.check_auth(&req).await;          // async, outside SM
engine.resume_and_execute(&flow_id, auth_data)?;            // sync, ~300ns
let resp    = backend.forward(&req).await;                  // async, outside SM
engine.resume_and_execute(&flow_id, resp_data)?;            // sync, ~300ns, terminal
```

`build()` validates 8 invariants at startup (reachability, DAG, at-most-one
External per state, requires/produces chain, etc.). If `build()` passes, the
flow is structurally correct. Full rationale: [tramli review in
volta-gateway](https://github.com/opaopa6969/tramli/blob/main/docs/review-volta-gateway.md).

## 3. Routing

`gateway/src/proxy.rs` (~1.3k LoC) holds `RoutingTable`, an `ArcSwap` wrapped
map keyed by host (exact + wildcard). Each `RouteTarget` carries:

- `backend` / `backends` (round-robin or weighted)
- optional `path_prefix` (used e.g. to route `/saml/*` to a Java sidecar — DD-005)
- `public`, `auth_bypass_paths`, `cors_origins`, `timeout_secs`
- `geo_allowlist` / `geo_denylist` (CF-IPCountry)
- `strip_prefix` / `add_prefix`, header add/remove rules
- `mirror` shadow backend (fire-and-forget, `sample_rate`)
- `plugins: Vec<PluginConfig>` — see [§5](#5-plugin-system).

Config sources (YAML + services.json + Docker labels + HTTP polling) are merged
by `ConfigMerger` into a single `RoutingTable` and hot-swapped via `ArcSwap`
on `SIGHUP` or `POST /admin/reload`.

## 4. tramli version policy

`tramli = "3.8"` is pinned across the workspace because:

1. `gateway`'s request FlowEngine and `auth-core`'s OIDC / MFA / Passkey /
   Invite flows share `FlowContext` types. A drift would produce compile errors.
2. Each minor upgrade (3.2 → 3.8) removed one piece of friction encountered in
   production. See [`docs/feedback.md`](feedback.md) for the round-trip.
3. `tramli-plugins = 3.6.1` introduces the `NoopTelemetrySink` used in the
   benchmark baseline (see `docs/benchmark-article.md`).

## 5. auth-server: the 5-merge router

`auth-server/src/app.rs` is where **96 Axum routes** are mounted. The router
is deliberately composed as *one core router* plus **five rate-limited
`route_layer` sub-routers** merged at the end:

```rust
Router::new()
    // ~ 80 non-rate-limited routes (auth, session, MFA setup, admin, SCIM, …)
    …
    .merge(oidc_routes)     // rl_oidc    10/min/IP
    .merge(mfa_routes)      // rl_mfa      5/min/IP
    .merge(passkey_routes)  // rl_passkey  5/min/IP
    .merge(invite_routes)   // rl_invite  20/min/IP
    .merge(magic_routes)    // rl_magic    5/min/IP
    .with_state(state)
```

Why this shape? Axum's `route_layer` only applies to routes declared *inside*
the sub-router. By colocating only the sensitive, brute-forceable endpoints in
their own sub-router and attaching the `RateLimiter` there, we avoid a global
middleware that would charge the other ~80 routes. Matches Java's per-endpoint
`@RateLimit(limit=N, window=60s)` annotations 1:1.

Each limiter is a `RateLimiter::new("oidc", 10, Duration::from_secs(60))`
instance keyed by client IP via `limit_by_ip` middleware.

Route taxonomy (see [`parity.md`](parity.md) for the full table):

| Category                   | Count | Examples |
|----------------------------|-------|----------|
| Auth (verify/logout/refresh/switch) | 6 | `/auth/verify`, `/auth/refresh` |
| OIDC                       | 3     | `/login`, `/callback`, `/auth/callback/complete` |
| SAML                       | 2     | `/auth/saml/login`, `/auth/saml/callback` |
| MFA (TOTP + challenge)     | 6     | `/mfa/challenge`, `/auth/mfa/verify` |
| Magic Link                 | 2     | `/auth/magic-link/send`, `/auth/magic-link/verify` |
| Passkey                    | 6     | `/auth/passkey/*`, `/api/v1/users/{id}/passkeys/*` |
| Sessions (user + admin)    | 7     | `/api/me/sessions`, `/admin/sessions` |
| User profile               | 2     | `/api/v1/users/me`, `/api/v1/users/me/tenants` |
| Tenant / Member / Invite   | 11    | `/api/v1/tenants/{id}`, `/invite/{code}/accept` |
| IdP / M2M / OAuth token    | 5     | `/api/v1/tenants/{id}/idp-configs`, `/oauth/token` |
| Webhooks                   | 6     | `/api/v1/tenants/{id}/webhooks[/id[/deliveries]]` |
| Admin API + HTML stubs     | 14    | `/api/v1/admin/*`, `/admin/*` |
| Billing / Policy / GDPR    | 7     | `/api/v1/tenants/{id}/billing`, `/api/v1/users/me/data-export` |
| SCIM 2.0                   | 8     | `/scim/v2/Users`, `/scim/v2/Groups` |
| Signing keys               | 3     | `/api/v1/admin/keys[/rotate|/{kid}/revoke]` |
| Viz + SSE                  | 3     | `/viz/flows`, `/viz/auth/stream`, `/api/v1/admin/flows/{id}/transitions` |
| Health + JWKS              | 2     | `/healthz`, `/.well-known/jwks.json` |
| **Total**                  | **~96** | |

## 6. auth-core flow library

`auth-core/src/flow/` holds four tramli `FlowDefinition`s ported 1:1 from
Java `volta-auth-proxy`:

| Flow file          | Purpose                                           |
|--------------------|---------------------------------------------------|
| `flow/oidc.rs`     | OIDC login lifecycle (INIT → REDIRECTED → CALLBACK → TOKEN → DONE) |
| `flow/mfa.rs`      | MFA TOTP challenge (PENDING → VERIFIED or FAILED) |
| `flow/passkey.rs`  | WebAuthn register + authenticate (2 state paths)  |
| `flow/invite.rs`   | Tenant invitation accept path                     |
| `flow/mermaid.rs`  | Mermaid renderer for the four flows above         |
| `flow/validate.rs` | Flow-definition validation helpers                |

These flows run inside `auth-core::AuthService`, the async orchestrator that
drives them with real IdP / Store / JWT backends. State persistence is handled
by `FlowPersistence` against the `auth_flows` + `auth_flow_transitions` tables
(optimistic locking).

Per DD-011, tramli in `auth-core` is used for *long-lived auth state* (login
attempts, challenges, invite lifecycles) — not per-HTTP-request. The per-request
machine in `gateway/src/flow.rs` is the only place where we create a
`FlowInstance` per request.

## 7. Plugin system

`gateway/src/plugin.rs` (~420 LoC) implements a **tramli-managed plugin
lifecycle**:

```text
LOADED ──▶ VALIDATED ──▶ ACTIVE ◀──▶ ERROR
                  │
                  └──▶ REJECTED  (validation failed)
```

### Phase 1: built-in native plugins

| Plugin             | Role                                                                 |
|--------------------|----------------------------------------------------------------------|
| `ApiKeyAuth`       | header/query/cookie-based API-key check for public routes.           |
| `RateLimitByUser`  | per-user rate limit, keyed by `X-Volta-User-Id` from auth-server.    |
| `Monetizer`        | billing header injector (`X-Monetizer-Plan`, `-Status`, `-Features`, `-Show-Ads`, `-Trial-End`). Built-in TTL cache with LRU safety valve (DD-016). |
| `HeaderInjector`   | static header add/remove per route.                                  |

Example YAML:

```yaml
routing:
  - host: api.example.com
    backend: http://localhost:3000
    plugins:
      - name: rate-limit-by-user
        config:
          limit: "60"
          window_secs: "60"
      - name: monetizer
        config:
          billing_url: "http://localhost:7080/billing"
          cache_ttl_secs: "30"
          cache_max_entries: "10000"
```

### Phase 2 (planned): Wasm sandboxed plugins

`plugin_type: wasm` is reserved in `PluginConfig`. `path:` points to a `.wasm`
file. Implementation (wasmtime) is deferred; see backlog.

## 8. Rate limiting — three layers

1. **Gateway global** (`gateway/src/...`): `tower::limit::RateLimitLayer` +
   global backpressure `Semaphore` — protects the process against connection
   floods.
2. **Gateway per-route / per-user**: `RateLimitByUser` plugin (plugin-scoped).
3. **auth-server per-endpoint**: the **5 `route_layer` limiters** in
   `auth-server/src/app.rs` (OIDC / MFA / Passkey / Invite / Magic Link).

A request that targets `/login` is therefore subject to (1) + (3). A request
that targets `/api/...` on a monetized route is subject to (1) + (2).

## 9. Security posture

| Layer                           | Threats mitigated                                              |
|---------------------------------|----------------------------------------------------------------|
| `hyper` HTTP parser             | request smuggling, header injection, HTTP/2 frame abuse        |
| `ProxyState::Validated`         | host-header poisoning, path traversal (literal + URL-encoded)  |
| AuthGuard                       | unauthenticated access; fail-closed on volta-auth-server down  |
| `auth_public_url` suffix match  | open-redirect on OIDC callbacks (`ad2a0a1`)                    |
| Response header strip           | backend `X-Volta-*` forgery                                     |
| Rate limiters (§8)              | OIDC / MFA brute force, invite spam                            |
| `subtle::ConstantTimeEq`        | timing attacks on HMAC / client secret compare                 |
| `security::reject_xml_doctype`  | XXE in SAML assertions                                         |
| `security::normalize_email` (NFC) | Unicode homoglyph abuse in invite/signup                     |
| `KeyCipher` (AES-GCM + PBKDF2)  | PKCE verifier exposure at rest                                 |

Full security ledger: Java upstream commit `abca91e` (#1–#21) ported 18 / 21
into Rust plus KeyCipher closes the remaining 3 in 0.3.0. See
`auth-server/docs/sync-from-java-2026-04-14.md`.

## 10. Observability

- Every state transition is timestamped with `durationMicros` (tramli 3.3+).
- `Prometheus /metrics` — latency histogram (8 buckets).
- `/admin/routes`, `/admin/backends`, `/admin/stats` — ops introspection
  (localhost-only).
- `/viz/auth/stream` — SSE auth event fan-out via Redis pub/sub.
- `/viz/flows` + `/api/v1/admin/flows/{id}/transitions` — tramli-viz hooks.

## 11. Reference

- [README](../README.md) / [README-ja](../README-ja.md)
- [Parity with Java](parity.md) / [日本語版](parity-ja.md)
- [Getting started](getting-started.md) / [日本語版](getting-started-ja.md)
- [tramli feedback loop](feedback.md)
- [HANDOFF — session notes](HANDOFF.md)
- [Backlog](backlog.md)
- [benchmark-article](benchmark-article.md)
- [migration-from-traefik](migration-from-traefik.md)
- Design Decisions: [DD-001 CORS default-deny](../dge/decisions/DD-001-cors-default-deny.md) ·
  [DD-002 L4 proxy scope](../dge/decisions/DD-002-l4-proxy-scope.md) ·
  [DD-005 Java→Rust migration](../dge/decisions/DD-005-java-to-rust-migration.md) ·
  [DD-006 Workspace](../dge/decisions/DD-006-auth-proxy-rs-repo.md).
