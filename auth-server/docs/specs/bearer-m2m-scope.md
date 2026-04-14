# Spec: Bearer M2M scope middleware (backlog P0 #3)

## Goal

Admin endpoints (`/api/v1/admin/*`, `/scim/v2/*`) must accept **both**:

1. Cookie session with `ADMIN` / `OWNER` role (existing)
2. `Authorization: Bearer <jwt>` issued by `/oauth/token` with `ADMIN` /
   `OWNER` scope

Today only (1) works — M2M clients cannot call admin APIs even after
obtaining a valid JWT.

## API

No new HTTP surface. `helpers::require_admin` extends to:

```text
1. if Authorization: Bearer <jwt>
     → verify with state.jwt_verifier
     → require "roles" claim to contain ADMIN or OWNER (case-insensitive)
     → on success: build a synthetic SessionRecord and return
     → on any failure: 401 INVALID_TOKEN (no cookie fallback)
2. else fall back to current cookie session check
```

The "no cookie fallback on Bearer failure" rule prevents attackers from
testing a token and silently being downgraded to a cookie path.

## Synthetic SessionRecord

When authorised via Bearer, `require_admin` returns a `SessionRecord`
populated from JWT claims:

| Field | Source |
|---|---|
| `session_id` | `"m2m-" + jti` (if present) else random |
| `user_id` | `sub` |
| `tenant_id` | `tenant_id` claim, else empty |
| `roles` | comma-split of `roles` claim |
| `email` / `display_name` | `None` |
| `expires_at` | `exp` claim |
| others | sane defaults |

Handlers consume this exactly like a cookie session — they only inspect
`user_id`, `tenant_id`, `roles`.

## Behaviour details

- Invalid JWT signature / expired → **401 INVALID_TOKEN**, no fallback.
- Valid JWT but no `ADMIN`/`OWNER` role → **403 INSUFFICIENT_SCOPE**.
- Both Cookie and Bearer present → Bearer wins. Cookie is ignored to
  keep the decision deterministic.

## Out of scope

- Fine-grained OAuth2 scopes (only coarse `ADMIN`/`OWNER`).
- Refresh tokens — `/oauth/token` returns opaque access tokens only.

## Success criteria

- `require_admin` unit tests cover: valid admin JWT / expired JWT /
  non-admin JWT / cookie-only / bearer-only / both-present.
