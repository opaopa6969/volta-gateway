# Arch: Bearer M2M scope middleware

## Decision

Extend `helpers::require_admin` to handle both Cookie and Bearer token
authentication. Do **not** split into two middlewares.

## Why one middleware, not two?

**Option A (rejected)**: separate `require_bearer_admin` for M2M routes,
keep `require_admin` for cookie routes. Pros: clearer separation.
Cons: every admin route has to pick one — M2M cannot reuse admin UI
paths and vice versa. Operators who want an M2M client to hit the same
`/api/v1/admin/users` endpoint as the browser session would need route
duplication.

**Option A picked (adopted)**: single entry point that tries Bearer
first, falls back to Cookie. Handlers don't care which path the caller
came from.

## Why "no cookie fallback on Bearer failure"?

If an attacker has stolen a partial token (revoked, expired, wrong sig)
and **also** a session cookie, naive fallback would silently succeed via
the cookie. That hides the Bearer rejection from logs and lets the
attacker confirm the token is dead.

Rule: **if `Authorization: Bearer` header is present, the Bearer path
decides. No fallback.** Missing header → cookie path as today.

## Synthetic SessionRecord

M2M callers don't have a DB session. We fabricate a `SessionRecord`
from JWT claims so handlers that expect `SessionRecord` don't need
ifs-and-elses. The only observable difference from a real session is
`session_id` prefixed with `"m2m-"` — handlers that log or audit can
distinguish if they care.

## Why not just return `AuthPrincipal`?

The `AuthPrincipal` pattern (Java's `AuthPrincipal`) would be cleaner
long-term but would require touching every admin handler signature.
Synthetic `SessionRecord` is the smaller change now; a future refactor
can swap types behind this same middleware entry point.

## JWT claim format (compat with `/oauth/token`)

`handlers::manage::oauth_token` issues tokens with:
```text
sub       = client.client_id
tenant_id = client.tenant_id
roles     = client.scopes (comma-separated)
```

So `require_admin` splits `roles` on comma and checks for ADMIN/OWNER.
M2M clients get these scopes from admin console at client creation.

## Alternatives considered

- **OAuth2 resource-server middleware (like tower-oauth2)**: overkill;
  brings JWKS / introspection that we don't need (HS256 tokens today).
- **Per-scope fine-grained middleware**: premature; all admin routes
  currently require the same ADMIN/OWNER level.
