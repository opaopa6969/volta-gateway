# Arch: Redis pub/sub SSE bridge

## Why Redis over NATS / Kafka

- Redis is already a common ops dependency for volta deployments
  (caching, rate-limit state).
- Pub/sub semantics are "at-most-once, no persistence" — which matches
  the visualization stream use case. We explicitly don't care about
  replaying events that were generated while a subscriber was down.
- NATS / Kafka would bring persistence & delivery guarantees we don't
  need and a bigger ops footprint.

## Why in-process broadcast remains authoritative

SSE clients subscribe to the local `AuthEventBus` regardless of
whether Redis is wired up. Redis is purely a "replicate into peer
buses" layer. Consequences:

- Single-instance deployments don't need Redis.
- If Redis dies at runtime, local fan-out keeps working.
- No dependency on Redis in hot SSE read paths — subscriber count
  scales with node-local clients only.

## Origin tagging

Each publish attaches `_origin = <random-hex>` to the JSON payload
before PUBLISHing. The local subscriber drops messages whose
`_origin` matches ours. Alternatives considered:

- **No tagging, trust Redis delivery shape**: wrong — Redis does not
  route away from the sender; we'd loop.
- **Two channels (publish-only, subscribe-only)**: extra ops surface
  with the same effect.
- **Timestamp dedup**: clock skew kills it.

Origin tag is also useful in logs to spot which node originated a
given auth event.

## Subscriber task lifecycle

- Spawn once on startup. Reconnect with backoff on `io::Error`.
- If `REDIS_URL` is unset, the task is never spawned and
  `AuthEventBus::publish` skips the PUBLISH branch.

## Why not tokio::sync::broadcast across nodes (via e.g. crossbeam)

Needs pairwise connections and connection failure handling we don't
want to write. Redis pub/sub is already a hub.
