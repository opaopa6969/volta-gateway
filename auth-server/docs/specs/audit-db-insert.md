# Spec: Audit DB insert (backlog P2 #10)

## Goal

Every auth event that the SSE bus emits is also persisted to the
`audit_logs` table. Today SSE publish is fire-and-forget; DB remains
empty for LOGIN_SUCCESS / LOGOUT / SESSION_EXPIRED.

## Event set

| Event | When | Source |
|---|---|---|
| `LOGIN_SUCCESS` | OIDC / Passkey / Magic-link / SAML callback succeeds | `handlers::oidc`, `passkey_flow`, `magic_link`, `saml` |
| `LOGOUT` | `/auth/logout` GET or POST | `handlers::auth` |
| `SESSION_EXPIRED` | ForwardAuth verify finds a session past `expires_at` | `handlers::auth::verify` (new) |
| `TENANT_SWITCH` | `/auth/switch-tenant` | `handlers::auth::switch_tenant` |
| `MFA_VERIFIED` | `/auth/mfa/verify` succeeds | `handlers::mfa` |
| `PASSKEY_REGISTERED` | `/api/v1/users/{id}/passkeys/register/finish` | `handlers::passkey_flow` |

SSE publish path is unchanged; DB insert is added alongside.

## Delivery semantics

- DB insert is **best-effort**: failures log at `warn` and don't fail
  the HTTP response. A failed insert shouldn't lock out the user.
- Both DB insert and SSE publish happen before the HTTP response
  returns — no background queue.
- `AuthEvent` carries enough context to construct an `AuditLogRecord`
  without additional DB reads.

## Mapping `AuthEvent` → `AuditLogRecord`

| AuditLogRecord field | Source |
|---|---|
| `event_type` | `event.event_type` |
| `actor_id` | `Uuid::parse(event.user_id)` (None → NULL) |
| `actor_ip` | looked up from request headers by the handler |
| `tenant_id` | `Uuid::parse(event.tenant_id)` (None → NULL) |
| `target_type` | `"SESSION"` for login/logout, `"USER"` for passkey register, etc. |
| `target_id` | `session_id` / `passkey_id` depending on event |
| `detail` | `event.detail` (JSON) |
| `request_id` | generated if not in headers (`X-Request-Id`) |
| `timestamp` | DB default `now()` |

## API

New helper in `auth_events.rs`:

```rust
impl AuthEventBus {
    /// Publish to SSE + persist to audit_logs. DB failure is non-fatal.
    pub async fn publish_and_audit(
        &self,
        ev: AuthEvent,
        db: &impl AuditStore,
        actor_ip: Option<&str>,
        request_id: Option<Uuid>,
    );
}
```

Handlers swap their `publish(...)` calls for `publish_and_audit(...)`.

## Success criteria

- Unit test: `publish_and_audit` inserts via a mock `AuditStore`.
- Unit test: DB insert failure logs but doesn't panic / propagate.
- Integration (once there is an integration harness): after a login,
  `SELECT * FROM audit_logs WHERE event_type='LOGIN_SUCCESS'` returns
  the new row.

## Out of scope

- Outbox → webhook delivery (the outbox worker already drains events
  published via `OutboxStore::enqueue`; today we don't enqueue audit
  events there — follow-up if we want external webhook subscribers).
