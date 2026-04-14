# Spec: Redis pub/sub SSE bridge (backlog P1 #7)

## Goal

`/viz/auth/stream` SSE events fan out across all auth-server replicas,
not just the process that handled the originating login/logout.

## Behaviour

- On startup, if `REDIS_URL` is set, spawn a subscriber task that
  listens on channel `volta:auth:events`. Messages received are pushed
  into the local `AuthEventBus` broadcast channel — SSE clients on this
  node see them.
- Every `AuthEventBus::publish` call also PUBLISHes the event to Redis,
  so peer nodes pick it up via their subscribers.
- A node never re-broadcasts an event that originated from Redis — we
  tag each publish with a short `origin` id and drop incoming messages
  matching our own id.

```
Node A login → publish → { local broadcast, redis PUBLISH }
Node B subscriber → local broadcast → SSE clients on B
Node A subscriber → receives own message → dropped (origin match)
```

If `REDIS_URL` is unset, the bus behaves exactly as today (in-process
only).

## Config

| Env | Default | Meaning |
|---|---|---|
| `REDIS_URL` | unset | `redis://host:port/db` — empty disables bridge |
| `REDIS_CHANNEL` | `volta:auth:events` | channel name |

Origin id is a random 8-byte hex generated at startup, attached as a
`_origin` field in the JSON payload before PUBLISH. Subscribers strip
this field before re-broadcasting locally.

## Failure modes

- Redis unavailable at startup: log warning, continue without bridge
  (in-process mode). Retry loop every 30 s.
- Redis drops mid-run: subscriber task exits; publishes silently skip
  the PUBLISH side, local fan-out still works.
- Subscriber delay: SSE clients on peer nodes see events 10-50 ms after
  the originating node — acceptable for a monitoring stream.

## Success criteria

- Unit test: `AuthEventBus` with bridge disabled equals today's behaviour.
- Integration test (manual, optional): spin up 2 instances behind
  lb, login on one, verify SSE stream on the other sees the event.
