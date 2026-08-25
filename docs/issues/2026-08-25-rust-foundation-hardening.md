# Rust foundation hardening

Status: implemented on 2026-08-25

## Context

The supported foundation is `volta-gateway` plus `volta-auth-server`. Java
`volta-auth-proxy` and Traefik are not part of the target topology.

## Security gaps

1. Local-network bypass was enabled by default and trusted client-controlled
   forwarding headers without proving that the transport peer was a gateway.
2. Route response cache keys did not contain user or tenant identity, but the
   cache could be enabled on authenticated routes and could store `Set-Cookie`.
3. Configuring a JWT verification key enabled an online-authorization bypass,
   even when degraded mode was disabled.
4. Backends trusted unsigned `X-Volta-*` identity headers.
5. The generated `min_role` field was ignored and auth-bypass prefixes were
   matched as unbounded strings.

## Acceptance criteria

- Local bypass is disabled unless `LOCAL_BYPASS_CIDRS` is explicitly set.
- Forwarded client IP headers affect bypass only when the Axum transport peer
  matches `LOCAL_BYPASS_TRUSTED_PROXY_CIDRS`.
- Shared response cache is rejected for routes without `public: true`; runtime
  code applies the same guard to hot/dynamic routes.
- Responses with `Set-Cookie`, authentication challenges, private/no-store
  cache control, or `Vary` are not stored.
- `/auth/verify` remains the primary path. Local JWT verification runs only
  after an online error and only with explicit `degraded_mode: true`.
- With an assertion secret configured, normal backend requests and Monetizer
  verification calls carry the signed assertion defined in
  [gateway-auth-trust-contract.md](../gateway-auth-trust-contract.md).
- Client-supplied assertion and identity headers never reach a backend.
- `min_role` is propagated and enforced with the five-role platform hierarchy;
  invalid/public/bypass combinations fail closed.
- Auth-bypass matching is segment-bounded and auth decision cache keys include
  URI, scheme, and resolved client IP.

## Follow-up

- Add key identifiers and dual-secret verification for zero-downtime assertion
  secret rotation.
- Replace the shared public-only response cache with explicit, reviewed
  `public | tenant | user` scopes before caching personalized content.
- Emit counters for rejected cache configurations and assertion signing errors.
