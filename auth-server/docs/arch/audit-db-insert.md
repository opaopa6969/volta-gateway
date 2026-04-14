# Arch: Audit DB insert

## Why combine with SSE publish (`publish_and_audit`)

Keeping the two paths together in one helper means handlers can't
accidentally publish one without the other. The alternative (two
separate calls) led to drift in the Java codebase (some endpoints
logged to DB but not SSE, and vice versa) — we avoid that here.

## Why best-effort DB insert

An auth endpoint's primary job is to issue / revoke sessions. DB
contention on `audit_logs` shouldn't cascade into user-facing 500s.
The trade-off: a brief DB outage loses audit rows.

Mitigation: the corresponding SSE event is still emitted, and any
external subscriber (a SIEM hooked into Redis) captures the event
regardless. Audit DB is the authoritative record for forensic replay,
not real-time alerting.

## No outbox fan-out

We considered routing every audit event through `OutboxStore::enqueue`
so the outbox worker delivers it to webhook subscribers. Rejected for
this milestone — the outbox table is currently business-event focused
(tenant lifecycle, billing). Auth events would 10x the row count for
a feature no current subscriber consumes.

Follow-up: if webhook subscribers want auth events, add a separate
`enqueue_audit` path with a dedicated event type prefix so consumers
can opt-in by filter.

## Request id

Read `X-Request-Id` header if the gateway filled it (it typically
does). Otherwise generate a per-event UUID so the row still has
something unique for correlation.

## actor_ip source order

1. `X-Real-IP` header (trusted — gateway fills it)
2. `X-Forwarded-For` first hop
3. peer socket addr

Handlers already resolve client IP via `rate_limit::client_ip_key`;
reuse that helper to keep the resolution consistent.
