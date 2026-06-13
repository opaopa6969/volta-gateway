# Auth degraded mode (fail-open for existing sessions)

> DD-005 / 縮退運転. Status: opt-in, off by default.
> In-process verification is now wired for **RS256 (JWKS / public-key PEM)** —
> the algorithm `volta-auth-proxy` actually issues — with HS256 kept for
> backward compatibility.

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
- **Requires an in-process verifier** (`jwks_url`, `jwt_public_key_pem`, or
  `jwt_secret`). Without one configured, there is nothing to fall back to and
  the gateway stays fail-closed even with degraded mode requested (a warning is
  logged at startup).
- **Default off.** This is a deliberate fail-open relaxation; it must be opted
  into per deployment.

## Enabling

Degraded mode is now a first-class `config.yaml` field, with the
`VOLTA_AUTH_DEGRADED_MODE` env var kept as an **env-priority fallback** (same
pattern as `admin.token` / `VOLTA_ADMIN_TOKEN`): when the env var is set to a
non-empty value it wins; otherwise the YAML value is used.

```yaml
auth:
  degraded_mode: true             # config field (default false)
```

```bash
VOLTA_AUTH_DEGRADED_MODE=true     # 1 / true / yes / on — overrides YAML
VOLTA_AUTH_DEGRADED_MODE=0        # explicitly disable, overriding YAML true
```

### In-process verifier config (RS256 is the production path)

`volta-auth-proxy` issues **RS256** session tokens (`iss=volta-auth`,
`aud=volta-apps`), so the production degraded-mode verifier should be keyed off
the proxy's signing key. Configure **either** a JWKS endpoint **or** a static
public-key PEM (JWKS wins when both are present); HS256 (`jwt_secret`) is an
optional backward-compat fallback.

```yaml
auth:
  cookie_name: __volta_session
  degraded_mode: true

  # Preferred: discover RS256 keys from the auth-proxy JWKS endpoint.
  # Cached with a TTL, refreshed in the background, and force-refreshed on a
  # kid miss. auth-proxy serves /.well-known/jwks.json.
  jwks_url: "http://auth-proxy:8080/.well-known/jwks.json"

  # Or: pin a static RS256 public key (inline PEM or a file path).
  jwt_public_key_pem: "/etc/volta/auth-proxy-pub.pem"

  # Enforce issuer/audience on RS256 tokens (recommended).
  jwt_issuer: "volta-auth"
  jwt_audience: "volta-apps"

  # Optional HS256 backward-compat fallback.
  jwt_secret: "${JWT_SECRET}"
```

**Verification order** (first success wins): `RS256(JWKS)` → `RS256(PEM)` →
`HS256(secret)`. If all sources are absent/invalid the token is rejected.

> Note: when an in-process verifier is configured, valid sessions are verified
> in-process *before* the HTTP roundtrip (Phase 0 fast path), so they survive an
> auth-proxy outage regardless. Degraded mode additionally covers the cases
> where the request falls through to the HTTP path (cookie not recognized by the
> fast path) and the proxy is unreachable.

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

- `gateway/src/config.rs` — `AuthConfig` carries `degraded_mode`,
  `jwks_url`, `jwt_public_key_pem`, `jwt_issuer`, `jwt_audience` (plus the
  legacy `jwt_secret`). `degraded_mode_enabled()` applies the env-priority
  override; `resolve_public_key_pem()` resolves inline-vs-path PEM.
- `gateway/src/auth.rs` — `VoltaAuthClient` builds a `SessionMultiVerifier`
  (wrapping auth-core's `MultiVerifier`) at construction, runs the in-process
  verify on the fast path, and `degraded_fallback()` implements the decision
  table above on auth-proxy failure. `spawn_jwks_refresher()` starts the JWKS
  background refresh task (called from `main.rs`). `degraded_total` is an
  in-process atomic counter.
- `auth-core/src/jwks.rs` — `JwksCache` (TTL cache, kid lookup, forced refresh
  on kid miss, background refresher) and `MultiVerifier` (RS256 JWKS → RS256
  PEM → HS256 chain, iss/aud enforcement). Reuses `jwt::JwtVerifier::new_rsa`
  semantics for RS256.

## Tests

`auth-core/src/jwks.rs`:

- RS256 PEM verifies a valid token; tampered signature rejected.
- iss/aud enforcement (wrong issuer / wrong audience rejected).
- HS256 fallback when no RS256 source matches; wrong HS256 secret rejected.
- JWKS kid selection (matching kid verifies, unknown kid rejected in sync path).
- JWKS refresh over HTTP, and async force-refresh on a cold cache / kid miss.

`gateway/src/auth.rs` (`degraded_tests`):

- auth-proxy down + valid JWT + degraded on → pass, metric increments.
- auth-proxy down + no cookie / invalid JWT + degraded on → fail-closed.
- degraded **off** → always fail-closed even with a valid JWT.
- degraded on but no verifier → stays fail-closed.
- `degraded_mode` from YAML; env override (on/0/empty) precedence over YAML.
- RS256 valid token survives proxy down; tampered / wrong-issuer rejected.
- `resolve_public_key_pem()` inline vs. file path.
- HS256 backward-compat alongside RS256 config.
- end-to-end `check()` against an unreachable proxy.
