# Arch: OIDC ID token validation

## JWKS caching strategy

**Decision**: in-memory `Mutex<HashMap<issuer, (fetched_at, JwkSet)>>`, 5
minute TTL. No distributed cache.

Alternatives:
- Redis-backed cache — rejected; another hop, same TTL guarantees.
- No cache (fetch per verification) — rejected; ~100 ms fetch per login
  is too slow for hot paths.
- Long-lived cache with explicit invalidation — rejected; adds an admin
  API surface. IdPs publish rotation windows anyway.

The 5 min TTL is tuned to the shortest OIDC rotation window we've seen
in the wild (Google: 24h, Microsoft: days, Apple: days). Key rotation
overlap (IdP keeps old key active for hours) covers the cache-miss gap.

## Why `jsonwebtoken` crate (not openidconnect crate's verifier)

The `openidconnect = "4"` dep is already in the tree but is heavier
than we need here — it handles the full OIDC flow state machine which
we don't use (we drive the flow ourselves with `oidc_flows`). The
`jsonwebtoken = "9"` crate gives us just JWS verification without
pulling in the rest. Claim validation is small enough to do by hand
and gives more control over error reasons.

## `aud` handling

OIDC allows `aud` to be either a single string or an array. We parse as
`Vec<String>` (single-string form is deserialised to a one-element vec
via a custom serde visitor).

## Skew tolerance

60 seconds either side on `exp` / `iat`. Same value Java uses.

## Decision on GitHub / non-OIDC providers

Verification is **opt-in per provider**:
- If `TokenResponse.id_token` is `None`, skip verification.
- If `IdpConfig.issuer_url` is `None`, skip verification (we have no
  JWKS URL to fetch).

Result: OIDC providers get full validation, OAuth2-only providers
continue to rely on `userinfo` as today. Operators who want stricter
mode can explicitly set `issuer_url` for providers that support it.

## Alternative considered: verify in `IdpClient` itself

Rejected — `IdpClient` currently manages only the raw OAuth2/OIDC
protocol; bundling JWKS cache there would grow the struct lifetime
concerns. Keeping `IdTokenVerifier` separate also lets tests
instantiate it with an injected JWK directly (no HTTP in unit tests).

## Why not verify `sub` matches `userinfo.sub`

A correct IdP returns the same `sub` in both, but some (Apple) return
different sub values for `userinfo` vs `id_token` in some edge cases.
We prefer `id_token.sub` when available, and fall back to `userinfo`
only when `id_token` is absent.
