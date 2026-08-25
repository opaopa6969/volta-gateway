# Issue: Rust-only foundation hardening

Priority: P0

Parent specification: [Rust-only Volta Foundation](../rust-only-foundation-spec.md)

## Goal

Make the Rust-only Volta stack safe for other services to depend on. Java
`volta-auth-proxy` and Traefik are explicitly out of scope.

## Delivery slices

### VGW-SEC-001 — Trusted identity hop

- [x] Strip client assertion headers at the edge.
- [x] Sign forwarded identity with gateway assertion v1.
- [x] Sign gateway monetizer-plugin calls.
- [x] Add a shared Rust/TypeScript contract vector and tamper/replay tests.
- [ ] Add key IDs and overlapping-key rotation; generation and current
      single-key operation are documented.

### VAUTH-SEC-001 — Safe client IP and bypass

- [x] Disable local-network bypass by default.
- [x] Use forwarding headers only for configured trusted peers.
- [x] Add direct-header-spoof regression tests.
- [x] Expose bypass activation at startup and mark bypassed responses.

### VGW-CACHE-001 — Cache isolation

- [x] Reject shared response cache on protected routes.
- [x] Reject credentialed requests and `Set-Cookie`, `private`, `no-store`,
      `Vary`, and authentication-challenge responses.
- [x] Add credential-isolation regression tests.
- [ ] Design explicit tenant/user cache scopes before enabling them.

### VAUTH-REV-001 — Online authorization semantics

- [x] Make local JWT verification degraded-mode-only.
- [ ] Add database-backed revocation, suspension, role-change, and MFA-change
      end-to-end cases.
- [ ] Define the production maximum offline authorization window.

### MON-SEC-001 — Monetizer boundary

- [x] Verify gateway assertion on authenticated and internal APIs.
- [x] Reject inactive plan listing and checkout.
- [x] Claim webhook events atomically and make persisted effects replay-safe.
- [x] Add a tenant-owned configuration migration issue and staged design.

### VPLAT-OPS-001 — Atomic convergence

- [x] Validate every API/CLI mutation with the same complete schema.
- [x] Await gateway regeneration and surface failures to callers.
- [x] Apply gateway config through temp/validate/atomic replace, bounded health
      verification, and rollback/reload.
- [x] Add managed-route ownership and snapshot-guarded safe deletion. Existing
      routes are not inferred as owned during bootstrap.
- [ ] Remove Traefik actions from active UI/API/runbooks.

## Acceptance criteria

1. The production topology starts no Java auth or Traefik process.
2. Direct spoofed identity headers cannot authorize a backend request.
3. A protected response cannot be observed by another identity through cache.
4. Duplicate webhook delivery cannot duplicate a persisted financial effect.
5. A control-plane API reports success only after desired state is validated
   and applied, or returns an actionable failure without damaging the previous
   config.
6. The Rust-only end-to-end path runs in blocking CI.
