[日本語版はこちら / Japanese](parity-ja.md)

# Rust ↔ Java Feature Parity

> **Scope:** every route exposed by `auth-server` (Rust) matched against
> `volta-auth-proxy` (Java). Gateway-only features (reverse proxy, plugin
> system, L4 proxy, TLS/ACME) are covered at the bottom.
>
> **Goal:** Rust ships the same *surface* as Java, so `volta-gateway` can
> replace the Java sidecar in `volta-bin` with no client-visible change.

Legend:

| Symbol | Meaning                                                           |
|--------|-------------------------------------------------------------------|
| ✅     | Implemented on both sides, behaviour verified                     |
| ⚠️     | Implemented with a documented caveat (see Notes column)           |
| 🚧     | Partial — route exists but scope reduced                          |
| ⏸     | Deferred — Java ships it, Rust intentionally not yet              |
| —      | Not applicable (gateway only / auth-proxy only)                   |

---

## Route parity (auth-server, ~96 endpoints)

Route list generated from `auth-server/src/app.rs`. Method column = Axum
method used at mount time.

### Auth lifecycle

| Method | Path                              | Rust | Java | Notes |
|--------|-----------------------------------|:----:|:----:|-------|
| GET    | `/auth/verify`                    | ✅   | ✅   | ForwardAuth; local-bypass + MFA-pending + tenant-suspend order per AUTH-010 |
| GET    | `/auth/logout`                    | ✅   | ✅   | — |
| POST   | `/auth/logout`                    | ✅   | ✅   | — |
| POST   | `/auth/refresh`                   | ✅   | ✅   | — |
| POST   | `/auth/switch-tenant`             | ✅   | ✅   | MFA state reset (`mfa_verified_at: None`) — Java #12 |
| POST   | `/auth/switch-account`            | ✅   | ✅   | — |
| GET    | `/select-tenant`                  | ✅   | ✅   | — |

### OIDC (rate-limited 10/min/IP)

| Method | Path                              | Rust | Java | Notes |
|--------|-----------------------------------|:----:|:----:|-------|
| GET    | `/login`                          | ✅   | ✅   | — |
| GET    | `/callback`                       | ✅   | ✅   | Rust uses HMAC-signed `state` (stateless); Java uses `consume_oidc_flow` atomic delete |
| POST   | `/auth/callback/complete`         | ✅   | ✅   | — |

### SAML

| Method | Path                              | Rust | Java | Notes |
|--------|-----------------------------------|:----:|:----:|-------|
| GET    | `/auth/saml/login`                | ✅   | ✅   | — |
| POST   | `/auth/saml/callback`             | ⚠️   | ✅   | Rust has XML-DSig path shipped 0.3.0, but production SAML still recommended via Java sidecar (`path_prefix: /saml/`) per DD-005 |

### MFA (TOTP + Magic Link)

| Method | Path                                                              | Rust | Java | Notes |
|--------|-------------------------------------------------------------------|:----:|:----:|-------|
| POST   | `/api/v1/users/{userId}/mfa/totp/setup`                           | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/mfa/totp/verify`                          | ✅   | ✅   | — |
| DELETE | `/api/v1/users/{userId}/mfa/totp`                                 | ✅   | ✅   | — |
| GET    | `/api/v1/users/me/mfa`                                            | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/mfa/recovery-codes/regenerate`            | ✅   | ✅   | — |
| GET    | `/mfa/challenge`                                                  | ✅   | ✅   | HTML TOTP input page (AUTH-010) |
| POST   | `/auth/mfa/verify`                                                | ✅   | ✅   | Rate limit 5/min/IP |
| POST   | `/auth/magic-link/send`                                           | ✅   | ✅   | Rate limit 5/min/IP |
| GET    | `/auth/magic-link/verify`                                         | ✅   | ✅   | Rate limit 5/min/IP |

### Passkey (WebAuthn)

| Method | Path                                                              | Rust | Java | Notes |
|--------|-------------------------------------------------------------------|:----:|:----:|-------|
| POST   | `/auth/passkey/start`                                             | ✅   | ✅   | Rate limit 5/min/IP |
| POST   | `/auth/passkey/finish`                                            | ✅   | ✅   | Rate limit 5/min/IP |
| POST   | `/api/v1/users/{userId}/passkeys/register/start`                  | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/passkeys/register/finish`                 | ✅   | ✅   | — |
| GET    | `/api/v1/users/{userId}/passkeys`                                 | ✅   | ✅   | — |
| DELETE | `/api/v1/users/{userId}/passkeys/{passkeyId}`                     | ✅   | ✅   | Sign-counter atomic UPDATE (Java #17) |

### Sessions

| Method | Path                                        | Rust | Java | Notes |
|--------|---------------------------------------------|:----:|:----:|-------|
| GET    | `/api/me/sessions`                          | ✅   | ✅   | — |
| DELETE | `/api/me/sessions`                          | ✅   | ✅   | Revoke all |
| DELETE | `/api/me/sessions/{id}`                     | ✅   | ✅   | — |
| DELETE | `/auth/sessions/{id}`                       | ✅   | ✅   | — |
| POST   | `/auth/sessions/revoke-all`                 | ✅   | ✅   | — |
| GET    | `/admin/sessions`                           | ✅   | ✅   | — |
| DELETE | `/admin/sessions/{id}`                      | ✅   | ✅   | — |

### User profile + admin users

| Method | Path                                        | Rust | Java | Notes |
|--------|---------------------------------------------|:----:|:----:|-------|
| GET    | `/api/v1/users/me`                          | ✅   | ✅   | — |
| GET    | `/api/v1/users/me/tenants`                  | ✅   | ✅   | — |
| PATCH  | `/api/v1/users/{userId}`                    | ✅   | ✅   | — |
| DELETE | `/api/v1/users/me`                          | ✅   | ✅   | — |
| POST   | `/api/v1/users/{userId}/export`             | ✅   | ✅   | — |

### Tenant / Member / Invitation

| Method | Path                                                   | Rust | Java | Notes |
|--------|--------------------------------------------------------|:----:|:----:|-------|
| POST   | `/api/v1/tenants`                                      | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}`                           | ✅   | ✅   | — |
| PATCH  | `/api/v1/tenants/{tenantId}`                           | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/transfer-ownership`        | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/members`                   | ✅   | ✅   | Paginated (`?page=&size=&sort=&q=`) |
| PATCH  | `/api/v1/tenants/{tenantId}/members/{memberId}`        | ✅   | ✅   | — |
| DELETE | `/api/v1/tenants/{tenantId}/members/{memberId}`        | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/invitations`               | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/invitations`               | ✅   | ✅   | Paginated |
| DELETE | `/api/v1/tenants/{tenantId}/invitations/{invitationId}`| ✅   | ✅   | — |
| POST   | `/invite/{code}/accept`                                | ✅   | ✅   | Rate limit 20/min/IP, NFC email normalize (Java #14) |

### IdP / M2M / OAuth2 token

| Method | Path                                                   | Rust | Java | Notes |
|--------|--------------------------------------------------------|:----:|:----:|-------|
| GET    | `/api/v1/tenants/{tenantId}/idp-configs`               | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/idp-configs`               | ✅   | ✅   | upsert |
| GET    | `/api/v1/tenants/{tenantId}/m2m-clients`               | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/m2m-clients`               | ✅   | ✅   | — |
| POST   | `/oauth/token`                                         | ✅   | ✅   | `client_credentials` grant, constant-time compare (Java #21) |

### Webhooks (Outbox pattern)

| Method | Path                                                               | Rust | Java | Notes |
|--------|--------------------------------------------------------------------|:----:|:----:|-------|
| POST   | `/api/v1/tenants/{tenantId}/webhooks`                              | ✅   | ✅   | SSRF guard: HTTPS only + private-IP reject (Java #1) |
| GET    | `/api/v1/tenants/{tenantId}/webhooks`                              | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}`                  | ✅   | ✅   | — |
| PATCH  | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}`                  | ✅   | ✅   | — |
| DELETE | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}`                  | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/webhooks/{webhookId}/deliveries`       | ✅   | ✅   | — |

### Audit / Devices / Billing / Policy / GDPR

| Method | Path                                                          | Rust | Java | Notes |
|--------|---------------------------------------------------------------|:----:|:----:|-------|
| GET    | `/api/v1/admin/audit`                                         | ✅   | ✅   | Paginated (`?page=&size=&from=&to=&event=`) |
| GET    | `/api/v1/users/me/devices`                                    | ✅   | ✅   | — |
| DELETE | `/api/v1/users/me/devices/{deviceId}`                         | ✅   | ✅   | — |
| DELETE | `/api/v1/users/me/devices`                                    | ✅   | ✅   | All |
| GET    | `/api/v1/tenants/{tenantId}/billing`                          | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/billing/subscription`             | ✅   | ✅   | — |
| GET    | `/api/v1/tenants/{tenantId}/policies`                         | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/policies`                         | ✅   | ✅   | — |
| POST   | `/api/v1/tenants/{tenantId}/policies/evaluate`                | ✅   | ✅   | — |
| POST   | `/api/v1/users/me/data-export`                                | ✅   | ✅   | — |
| DELETE | `/api/v1/users/{userId}/data`                                 | ✅   | ✅   | Hard delete extended to outbox_events + auth_flow_transitions (Java #18) |

### Admin (system)

| Method | Path                                                          | Rust | Java | Notes |
|--------|---------------------------------------------------------------|:----:|:----:|-------|
| GET    | `/api/v1/admin/tenants`                                       | ✅   | ✅   | — |
| GET    | `/api/v1/admin/users`                                         | ✅   | ✅   | Paginated |
| GET    | `/api/v1/admin/sessions`                                      | ✅   | ✅   | Paginated |
| POST   | `/api/v1/admin/outbox/flush`                                  | ✅   | ✅   | — |
| GET    | `/api/v1/admin/keys`                                          | ✅   | ✅   | — |
| POST   | `/api/v1/admin/keys/rotate`                                   | ✅   | ✅   | — |
| POST   | `/api/v1/admin/keys/{kid}/revoke`                             | ✅   | ✅   | — |
| GET    | `/admin/members`                                              | 🚧   | ✅   | HTML stub |
| GET    | `/admin/invitations`                                          | 🚧   | ✅   | HTML stub |
| GET    | `/admin/webhooks`                                             | 🚧   | ✅   | HTML stub |
| GET    | `/admin/idp`                                                  | 🚧   | ✅   | HTML stub |
| GET    | `/admin/tenants`                                              | 🚧   | ✅   | HTML stub |
| GET    | `/admin/users`                                                | 🚧   | ✅   | HTML stub |
| GET    | `/admin/audit`                                                | 🚧   | ✅   | HTML stub |
| GET    | `/settings/security`                                          | 🚧   | ✅   | HTML stub |
| GET    | `/settings/sessions`                                          | 🚧   | ✅   | HTML stub |

### SCIM 2.0

| Method | Path                                                  | Rust | Java | Notes |
|--------|-------------------------------------------------------|:----:|:----:|-------|
| GET    | `/scim/v2/Users`                                      | ✅   | ✅   | — |
| POST   | `/scim/v2/Users`                                      | ✅   | ✅   | — |
| GET    | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| PUT    | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| PATCH  | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| DELETE | `/scim/v2/Users/{id}`                                 | ✅   | ✅   | — |
| GET    | `/scim/v2/Groups`                                     | ✅   | ✅   | — |
| POST   | `/scim/v2/Groups`                                     | ✅   | ✅   | — |

### Visualization + Health

| Method | Path                                                  | Rust | Java | Notes |
|--------|-------------------------------------------------------|:----:|:----:|-------|
| GET    | `/viz/auth/stream`                                    | ✅   | ✅   | SSE via Redis pub/sub (`auth_events::AuthEventBus`) |
| GET    | `/viz/flows`                                          | ✅   | ✅   | tramli-viz static list |
| GET    | `/api/v1/admin/flows/{flowId}/transitions`            | ✅   | ✅   | — |
| GET    | `/healthz`                                            | ✅   | ✅   | — |
| GET    | `/.well-known/jwks.json`                              | ✅   | ✅   | Signing-key rotation aware |

---

## Gateway feature parity (gateway crate vs Traefik / Java sidecar)

| Feature                                    | volta-gateway | Java `volta-auth-proxy` sidecar | Notes |
|--------------------------------------------|:-------------:|:-------------------------------:|-------|
| HTTP/1.1 + HTTP/2                          | ✅            | ✅ (behind nginx)               | hyper auto-negotiation |
| WebSocket tunnel                           | ✅            | ✅                              | 1024 conn limit |
| TLS + Let's Encrypt (ACME TLS-ALPN-01)     | ✅            | — (nginx)                       | rustls-acme |
| Let's Encrypt DNS-01 (Cloudflare)          | ✅            | —                               | instant-acme |
| Round-robin / weighted LB                  | ✅            | —                               | — |
| Circuit breaker                            | ✅            | ✅                              | 5 fails / 30s recovery, Retry-After |
| Auth cache                                 | ✅            | ✅                              | 5s TTL cookie-based |
| Gzip / brotli compression                  | ✅            | ✅ (nginx)                      | streaming |
| CORS (per-route, secure-by-default)        | ✅            | ⚠️                              | Java defaulted to permissive; Rust DD-001 = deny |
| Custom error pages                         | ✅            | ✅                              | — |
| Hot reload (SIGHUP + `/admin/reload`)      | ✅            | ⚠️                              | Rust: zero-downtime `ArcSwap` |
| Public routes / `auth_bypass_paths`        | ✅            | ✅                              | — |
| `strip_prefix` / `add_prefix`              | ✅            | ✅                              | — |
| Header add/remove per route                | ✅            | ✅                              | — |
| Traffic mirroring (shadow backend)         | ✅            | —                               | fire-and-forget, `sample_rate` |
| Geo allowlist / denylist (CF-IPCountry)    | ✅            | —                               | — |
| Per-route timeout                          | ✅            | —                               | `timeout_secs` |
| W3C `traceparent` propagation              | ✅            | ✅                              | — |
| Response cache (LRU + TTL)                 | ✅            | —                               | `X-Volta-Cache: HIT/MISS` |
| Plugin system (native Rust)                | ✅            | —                               | `ApiKeyAuth`, `RateLimitByUser`, `Monetizer`, `HeaderInjector` |
| Plugin system (Wasm)                       | ⏸            | —                               | Phase 2 backlog |
| Config sources (YAML + services.json + Docker labels + HTTP poll) | ✅ | — | hot-reload merged via `ArcSwap` |
| Backend health check                       | ✅            | —                               | — |
| mTLS backend                               | ✅            | —                               | — |
| Global backpressure (`Semaphore`)          | ✅            | —                               | — |
| Admin API (`/admin/{routes,backends,stats,reload,drain}`) | ✅ | —                    | localhost-only |
| `--validate` config check                  | ✅            | —                               | CI/CD |
| L4 proxy (TCP/UDP)                         | ✅            | —                               | DD-002: not auth-gated |
| Prometheus `/metrics`                      | ✅            | ✅                              | 8-bucket histogram |
| Trusted proxies (CF-Connecting-IP / X-Real-IP) | ✅         | ✅                              | — |
| Mesh VPN integration (Headscale)           | ✅            | —                               | `docs/MESH-VPN-SPEC.md` |

---

## Known gaps vs Java

| # | Gap                                              | Reason                                                              | Tracker |
|---|--------------------------------------------------|---------------------------------------------------------------------|---------|
| 1 | Admin HTML pages are stubs                       | Not on critical path; Java pages ported when admin UI stabilises    | [backlog] P5-6 |
| 2 | Production-grade SAML signature (`xmlsec`)       | Using Rust-side simplified path; Java sidecar is recommended        | DD-005  |
| 3 | Full Wasm plugin runtime                         | Native plugins cover current needs; wasmtime integration deferred   | [backlog] |

---

## How to verify

```bash
# Rust
cargo test --workspace

# auth-server unit + integration
cargo test -p volta-auth-server --bins      # 44 unit tests
cargo test -p volta-auth-core --features postgres -- --ignored  # integration

# Route count sanity check (should print ~96)
rg -c '^\s+\.route\(' auth-server/src/app.rs
```

See also [`auth-server/docs/sync-from-java-2026-04-14.md`](../auth-server/docs/sync-from-java-2026-04-14.md)
for the commit-level trace from each Java change to its Rust landing spot.
