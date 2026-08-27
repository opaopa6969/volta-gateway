# Rust-only Volta Foundation Specification

Status: Accepted for implementation (2026-08-25)

## 1. Decision

The supported Volta foundation is:

```text
Cloudflare/TLS
      |
      v
volta-gateway (Rust edge and policy enforcement point)
      |----> volta-auth-server (Rust identity and authorization)
      |----> volta-monetizer (billing and entitlement)
      `----> application backends

volta-platform -> desired state, validation, atomic gateway apply, audit
```

Java `volta-auth-proxy` and Traefik are not runtime components of the target
architecture. Documents comparing or migrating from them are historical
material and must not be used as current deployment guidance.

## 2. Trust boundaries

1. Only `volta-gateway` accepts application traffic from the edge.
2. Backends do not trust client-supplied `X-Volta-*`,
   `X-Volta-Assertion-*`, client-IP, or forwarding headers.
3. The gateway removes those headers before adding verified identity and a
   gateway assertion.
4. `volta-auth-server`, monetizer, databases, Redis, admin APIs, and control
   plane executors are private services. Direct public routing is invalid.
5. Trusted proxy headers are accepted only when the direct peer belongs to an
   explicitly configured trusted-proxy CIDR.
6. Local-network authentication bypass is disabled by default. Enabling it is
   an explicit, audited exception, not a deployment default.

## 3. Gateway assertion v1

Gateway-to-backend identity is authenticated with these headers:

- `X-Volta-Assertion-Timestamp`: Unix timestamp in seconds.
- `X-Volta-Assertion-Signature`: `v1=<lowercase hex HMAC-SHA256>`.

The HMAC key is supplied through `VOLTA_GATEWAY_ASSERTION_SECRET` (recommended)
or `auth.gateway_assertion_secret` and must be at least 32 bytes. It is never
stored in route configuration or `services.json`.

The UTF-8 canonical payload is:

```text
v1\n
<timestamp>\n
<HTTP method>\n
<forwarded path and query>\n
<X-Volta-User-Id>\n
<X-Volta-Tenant-Id>\n
<X-Volta-Roles>
```

The path is the path seen by the backend after gateway rewriting. Missing
identity values are encoded as empty strings. Consumers must use a
constant-time comparison, reject unsupported versions, reject timestamps
outside the configured skew window, and fail closed when assertion validation
is enabled but the secret/signature is absent.

The assertion authenticates the gateway hop and identity headers. It is not a
replacement for request idempotency, CSRF protection, or authorization inside
the consumer.

## 4. Authentication behavior

- Normal requests are authorized by `volta-auth-server`.
- Local JWT verification is an explicit degraded-mode fallback only. It must
  not silently replace online checks because revocation, tenant suspension,
  MFA state, and policy changes are server-side decisions.
- A cached authorization result may have a short bounded TTL, but its key must
  include every policy input: session, host, application, URI, scheme, and
  resolved client IP.
- Bypass paths use exact or segment-bounded matching. Health endpoints must use
  exact matching.
- `min_role` is enforced by the gateway using
  `OWNER > ADMIN > OPERATOR > MEMBER > VIEWER`. It is the route default and
  may combine with `auth_bypass_paths`; a matching bypass path skips both
  authentication and the `min_role` check. Only `public: true` combined with
  `min_role` fails closed (route-wide skip conflicts with a role requirement).

## 5. Response cache behavior

- Protected responses are not shared across identities.
- The initial safe implementation only permits the shared response cache on
  public routes.
- `Set-Cookie` responses and responses marked `private` or `no-store` are never
  cached.
- Requests carrying `Cookie` or `Authorization` never use the shared cache,
  even on public routes.
- A future authenticated cache must declare `public`, `tenant`, or `user`
  scope and include that scope's identity in the key.

## 6. Monetizer behavior

- User-facing monetizer APIs validate the gateway assertion before consuming
  `X-Volta-*` identity.
- Internal verify/invalidate APIs also require a valid gateway service
  assertion.
- Webhook delivery is claimed atomically before effects are applied. Duplicate
  deliveries cannot execute billing effects twice.
- Inactive plans are neither listed nor purchasable.
- The long-term ownership key is `tenant_id`; migration from user-owned config
  is tracked separately because it changes persisted data and API semantics.

## 7. Control-plane apply protocol

Every desired-state mutation follows:

```text
authenticate -> validate complete service -> atomic desired-state write
-> render temporary gateway config -> gateway validate
-> atomic replace -> reload -> bounded health/convergence check -> audit result
```

An API must not report a successful converged change while route generation or
application is still running in the background. Managed routes need ownership
metadata so deletion can remove only generated state without preserving stale
public or backend configuration.

## 8. Release gates

Required blocking gates:

- format, lint, compile, unit and integration tests;
- PostgreSQL migration tests on a clean database and an upgraded database;
- spoofed-header, trusted-proxy, cache-isolation, webhook-concurrency, and
  inactive-plan security tests;
- dependency, secret, and container scanning;
- a Rust gateway + Rust auth + monetizer end-to-end test without Java or
  Traefik processes.
