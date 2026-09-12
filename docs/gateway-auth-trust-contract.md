---
status: current
canonicalFor: gateway-auth-trust-contract
contractVersion: auth-edge/1.0.0
lastVerified: 2026-09-12
language: en
supersedes: []
---

# Gateway/auth trust contract

**Owner:** `volta-gateway`

**Contract version:** `auth-edge/1.0.0`

**Wire assertion version:** `v1`

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
X-Volta-Assertion-Key-Id: <active key ID>
X-Volta-Assertion-Timestamp: <Unix seconds>
X-Volta-Assertion-Signature: v1=<lowercase hex HMAC-SHA256>
```

The successful auth response may supply these identity headers. The gateway
forwards them only after stripping the client's `X-Volta-*` namespace:

| Header | Meaning | Presence |
| --- | --- | --- |
| `X-Volta-User-Id` | authenticated subject ID | authenticated user or temporary grant |
| `X-Volta-Email` | subject email | when known |
| `X-Volta-Tenant-Id` | active tenant ID | tenant-scoped user |
| `X-Volta-Tenant-Slug` | active tenant slug | when resolved |
| `X-Volta-Roles` | comma-separated roles | authenticated user |
| `X-Volta-Display-Name` | display name | when known |
| `X-Volta-JWT` | short-lived signed identity JWT | session authentication |
| `X-Volta-Auth-Source` | `bearer`, `temporary-access`, or `local-bypass` | non-default auth path |
| `X-Volta-Token-Id` | bearer/temporary grant identifier | token authentication |
| `X-Volta-Scope` | space-delimited bearer scopes | when granted |

`X-Volta-App-Id` and `X-Volta-Required-Role` travel from gateway to
auth-server as policy inputs. They are not backend identity assertions.

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

`X-Volta-Assertion-Key-Id` selects the current or previous key during rotation.
When more than one verification key is configured, consumers must reject a
missing or unknown key ID. A single-key migration may accept a missing key ID
only for the legacy key.

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

## Ownership and compatibility

This document is the canonical contract for the gateway/auth boundary and the
`X-Volta-*` namespace. `volta-auth-server`, in this repository, is the online
identity producer; `volta-gateway` is the enforcing edge and downstream header
producer. Other repositories are consumers and link here instead of copying
the header contract.

- Adding an optional identity header is backwards-compatible and increments
  the document contract's minor version.
- Tightening validation without changing the signed canonical form increments
  the patch version when existing conforming consumers remain valid.
- Removing/renaming a header, changing its meaning or encoding, or changing the
  HMAC canonical form is breaking. It requires a new major contract version and
  a new signature prefix (`v2=...`), with an overlap window for both versions.
- Consumers ignore unknown optional identity headers but fail closed on an
  unknown assertion signature version, missing required signed fields, or an
  invalid assertion.

## Migration and revert

For compatible additions, deploy auth-server first, gateway second, and
consumers last. For a breaking version, deploy dual-version consumer
verification first, then a gateway capable of emitting the new version, switch
producers, observe the overlap window, and only then remove `v1` acceptance.

To revert a compatible documentation or optional-header release, revert the
gateway merge and leave consumers accepting the optional header. To revert a
breaking rollout during its overlap window, switch gateway emission back to
`v1`; do not remove the old verification key or `v1` consumer path until the
rollback window has closed.
