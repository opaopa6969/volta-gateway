# Auth degraded mode (fail-open for existing sessions)

> DD-005 / 縮退運転. Status: opt-in, off by default.

## Problem

The gateway's primary authorization path is an HTTP call to
`volta-auth-proxy` (`/auth/verify`). When that proxy times out (default 500 ms)
or returns 5xx, the gateway is **fail-closed**: every request gets a `502`.

That is the safe default, but it means a single auth-proxy outage takes down
*all* protected apps — even for users who already hold a valid, signed session
cookie that the gateway could verify on its own.

## What degraded mode does

When degraded mode is enabled **and** the auth-proxy call fails
(`AuthResult::Error` — timeout or 5xx), the gateway falls back to
**in-process RS256/HS256 JWT verification** of the session cookie
(reusing the Phase 0 `SessionVerifier` / `JwtVerifier` in `auth-core`):

| Situation (auth-proxy down)        | degraded off | degraded on            |
| ---------------------------------- | ------------ | ---------------------- |
| Valid session JWT in cookie        | 502          | **pass** (warn + metric) |
| No session cookie                  | 502          | 502 (fail-closed)      |
| Expired / invalid / wrong-sig JWT  | 502          | 502 (fail-closed)      |

In other words: degraded mode keeps **existing logged-in sessions alive**
while the auth-proxy is down. It never authenticates anyone new.

## Important operational caveats

- **No new logins.** Login, MFA, OIDC/SAML callbacks, refresh — everything that
  *mints* a session — still requires the auth-proxy. Degraded mode only
  *verifies* a cookie the user already has. A user whose session expires during
  the outage cannot log back in until the proxy recovers.
- **No revocation / policy re-check.** The fallback only checks the JWT
  signature and `exp`. Any authorization the auth-proxy does *beyond* the token
  (role/policy lookups, session revocation lists, IP rules) is **not** applied
  during the fallback. Treat degraded mode as "trust the signed token as-is".
- **Requires `jwt_secret` (or RSA public key).** Without an in-process verifier
  configured, there is nothing to fall back to and the gateway stays
  fail-closed even with degraded mode requested (a warning is logged at
  startup).
- **Default off.** This is a deliberate fail-open relaxation; it must be opted
  into per deployment.

## Enabling

Degraded mode is opt-in via environment variable (config-file plumbing is
intentionally kept out of this change to avoid clashing with the config
refactor; it can be promoted to a `config.yaml` `auth.degraded_mode` field
later):

```bash
VOLTA_AUTH_DEGRADED_MODE=true    # 1 / true / yes / on
```

It requires an in-process verifier, i.e. the existing Phase 0 config:

```yaml
auth:
  jwt_secret: "${JWT_SECRET}"     # enables in-process JWT verification
  cookie_name: __volta_session
```

> Note: in a deployment where `jwt_secret` is set, valid sessions are already
> verified in-process *before* the HTTP roundtrip (Phase 0 fast path), so they
> survive an auth-proxy outage regardless. Degraded mode additionally covers
> the cases where the request falls through to the HTTP path (e.g. cookie not
> recognized by the fast path) and the proxy is unreachable.

## Observability

- **Log:** every fallback emits a `WARN` with `auth_degraded_total`, the host,
  and the underlying auth error. Enabling degraded mode at startup also logs a
  `WARN` so it's visible in boot logs.
- **Metric:** `/metrics` exposes a Prometheus counter:

  ```
  # TYPE auth_degraded_total counter
  auth_degraded_total <n>
  ```

  A non-zero (or rising) `auth_degraded_total` means the auth-proxy is
  unhealthy and the gateway is currently coasting on signed sessions —
  page on it.

## Design / code

- `gateway/src/auth.rs` — `VoltaAuthClient::degraded_fallback()` implements the
  decision table above; `degraded_mode` is read from the env at construction,
  and `degraded_total` is an in-process atomic counter.
- `auth-core` — `session::SessionVerifier` + `jwt::JwtVerifier` (HS256 today,
  `JwtVerifier::new_rsa` for RS256) provide the in-process verification reused
  here.

## Tests

`gateway/src/auth.rs` (`degraded_tests`):

- auth-proxy down + valid JWT + degraded on → pass, metric increments.
- auth-proxy down + no cookie + degraded on → fail-closed.
- auth-proxy down + invalid JWT + degraded on → fail-closed.
- degraded **off** → always fail-closed even with a valid JWT.
- degraded on but no `jwt_secret` → stays fail-closed.
- end-to-end `check()` against an unreachable proxy.
