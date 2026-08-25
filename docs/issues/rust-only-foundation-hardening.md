# Issue: Rust-only foundation hardening

Priority: P0

Parent specification: [Rust-only Volta Foundation](../rust-only-foundation-spec.md)

## Goal

Make the Rust-only Volta stack safe for other services to depend on. Java
`volta-auth-proxy` and Traefik are explicitly out of scope.

## Delivery slices

### VGW-SEC-001 — Trusted identity hop

- [ ] Strip client assertion headers at the edge.
- [ ] Sign forwarded identity with gateway assertion v1.
- [ ] Sign gateway monetizer-plugin calls.
- [ ] Add tamper, expiry, path, method, user, tenant, and role tests.
- [ ] Document secret generation and rotation.

### VAUTH-SEC-001 — Safe client IP and bypass

- [ ] Disable local-network bypass by default.
- [ ] Use forwarding headers only for configured trusted peers.
- [ ] Add direct-header-spoof regression tests.
- [ ] Expose bypass activation and usage as startup/audit signals.

### VGW-CACHE-001 — Cache isolation

- [ ] Reject shared response cache on protected routes.
- [ ] Reject `Set-Cookie`, `private`, and `no-store` responses.
- [ ] Add two-user isolation tests.
- [ ] Design explicit tenant/user cache scopes before enabling them.

### VAUTH-REV-001 — Online authorization semantics

- [ ] Make local JWT verification degraded-mode-only.
- [ ] Test session revocation, tenant suspension, role change, and MFA change.
- [ ] Define maximum offline authorization window.

### MON-SEC-001 — Monetizer boundary

- [ ] Verify gateway assertion on authenticated and internal APIs.
- [ ] Reject inactive plan listing and checkout.
- [ ] Claim webhook events atomically before side effects.
- [ ] Add tenant-owned configuration migration design.

### VPLAT-OPS-001 — Atomic convergence

- [ ] Validate every API/CLI mutation with the same complete schema.
- [ ] Await gateway regeneration and surface failures to callers.
- [ ] Apply gateway config through temp/validate/atomic replace.
- [ ] Add managed-route ownership and safe deletion.
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
