# Gateway/auth trust contract

This contract applies to the Rust topology: `volta-gateway` is the only public
edge and `volta-auth-server` is the online authorization authority.

## Online authorization and degraded mode

Every protected request calls `/auth/verify`, including requests with a locally
valid JWT. A timeout, connection error, or unexpected 5xx fails closed unless
`auth.degraded_mode: true` is explicitly enabled. Only then may the gateway
verify an existing signed session locally. Local verification does not replace
normal revocation, tenant-status, role, MFA, or policy checks.

## Client IP and local bypass

Local bypass is disabled by default. Enabling it requires:

```text
LOCAL_BYPASS_CIDRS=100.64.0.0/10
LOCAL_BYPASS_TRUSTED_PROXY_CIDRS=10.42.0.0/16
```

The peer socket address is authoritative. `X-Real-IP` and the first
`X-Forwarded-For` entry are used only if that peer belongs to the trusted-proxy
set. Requests without peer information cannot use forwarded headers.

## Backend assertion

Set `VOLTA_GATEWAY_ASSERTION_SECRET` or
`auth.gateway_assertion_secret` to the same random value (at least 32 bytes) in
the gateway and internal consumers. The environment variable takes precedence.

The gateway strips all client-supplied `X-Volta-*` headers, adds the identity
returned by auth-server, then sends:

```text
X-Volta-Assertion-Timestamp: <Unix seconds>
X-Volta-Assertion-Signature: v1=<lowercase hex HMAC-SHA256>
```

The HMAC input is UTF-8 with literal newlines and no final newline:

```text
v1
<timestamp>
<uppercase method>
<forwarded path-with-query>
<X-Volta-User-Id>
<X-Volta-Tenant-Id>
<X-Volta-Roles>
```

For the gateway's internal Monetizer verification call the identity fields are
empty; the signed path/query still binds `user` and `config`.

Consumers must reject a missing/unknown version, invalid hex/MAC, or timestamp
outside their replay window, and must compare MAC bytes in constant time.
Production backends that consume `X-Volta-User-Id`, `X-Volta-Tenant-Id`, or
`X-Volta-Roles` must configure this secret and reject unsigned requests.

Cross-service test vector:

```text
secret: 0123456789abcdef0123456789abcdef
timestamp: 1700000000
method: GET
path/query: /v1/items?q=1
user: user-1
tenant: tenant-1
roles: ADMIN,MEMBER
signature: v1=bb4fb0ab85dbaf12f10b29e2fe436b2d5eeb6d836c40255fed4a9fd41cd5f568
```

## Route authorization

`min_role` uses `OWNER > ADMIN > OPERATOR > MEMBER > VIEWER` and is enforced
only after a successful online/degraded authentication result. Unknown roles
fail config validation. `min_role` may be combined with `auth_bypass_paths`:
the `min_role` is the route default, and a matching bypass path skips both
authentication and the `min_role` check (health external probes etc.). Only
`public: true` combined with `min_role` fails closed with 403 (it is a
route-wide auth skip and conflicts with a role requirement).

Auth-bypass prefixes match path-segment boundaries: `/health` matches
`/health` and `/health/ready`, but not `/healthz` or `/health-secret`.

The short-lived auth decision cache varies by cookie, host, URI, scheme,
application ID, and resolved client IP so a decision cannot cross a policy
boundary.

## Shared response cache

The current cache is route-wide. Therefore `cache.enabled: true` requires
`public: true`. Authenticated routes, including routes with only selected
`auth_bypass_paths`, cannot use it. `Set-Cookie`, `Vary`, authentication
challenge, `private`, and `no-store` responses are never stored.
Requests carrying `Cookie` or `Authorization` bypass both cache lookup and
storage, including on public routes.
