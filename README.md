[日本語版はこちら / Japanese](README-ja.md)

# volta-gateway

Auth-aware reverse proxy powered by state machine.

**Every request rides on rails** — the state machine ensures that only valid transitions happen. No request smuggling. No forgotten auth checks. No invisible failures.

> **Why build your own proxy?** Because Traefik's ForwardAuth adds 4-10ms per request (2 HTTP round-trips). volta-gateway does it in 0.5-1ms (localhost, 1 round-trip). And every step is visible.

## How it works

```
Client → Cloudflare (TLS) → volta-gateway (HTTP:8080) → volta-auth-proxy (auth check)
                                                       → Backend App

Request lifecycle (state machine):
  RECEIVED → VALIDATED → ROUTED → [auth] → AUTH_CHECKED → [forward] → FORWARDED → COMPLETED
                                            ├── REDIRECT (login)
                                            ├── DENIED (403)
                                            └── BAD_GATEWAY (volta down)
```

### State Chart

```mermaid
stateDiagram-v2
    [*] --> Received
    Received --> Validated : RequestValidator
    Validated --> Routed : RoutingResolver
    Routed --> AuthChecked : [AuthGuard] ← volta /auth/verify
    AuthChecked --> Forwarded : [ForwardGuard] ← backend HTTP
    Forwarded --> Completed : CompletionProcessor

    Received --> BadRequest : headers too large
    Validated --> BadRequest : unknown host / invalid path
    Routed --> Redirect : 401 (unauthenticated)
    Routed --> Denied : 403 (forbidden)
    Routed --> BadGateway : volta down / timeout
    AuthChecked --> BadGateway : backend error
    AuthChecked --> GatewayTimeout : backend timeout

    Completed --> [*]
    BadRequest --> [*]
    Redirect --> [*]
    Denied --> [*]
    BadGateway --> [*]
    GatewayTimeout --> [*]
```

This diagram is **generated from the same `FlowDefinition`** that the engine executes. Code = diagram. Always in sync.

Every state transition is logged. You can see **exactly** where time was spent:

```json
{
  "transitions": [
    {"from": "RECEIVED", "to": "VALIDATED", "duration_us": 5},
    {"from": "VALIDATED", "to": "ROUTED", "duration_us": 2},
    {"from": "ROUTED", "to": "AUTH_CHECKED", "duration_us": 850},
    {"from": "AUTH_CHECKED", "to": "FORWARDED", "duration_us": 12500}
  ],
  "total_us": 13360
}
```

## Quick Start

```bash
# 1. Clone
git clone https://github.com/opaopa6969/volta-gateway
cd volta-gateway

# 2. Configure (edit routing to match your backends)
cp volta-gateway.yaml my-config.yaml
# Edit my-config.yaml

# 3. Make sure volta-auth-proxy is running on localhost:7070

# 4. Run
cargo run -- my-config.yaml
```

## Configuration

```yaml
server:
  port: 8080

auth:
  volta_url: http://localhost:7070   # volta-auth-proxy
  timeout_ms: 500                    # fail-closed: volta down → 502

routing:
  - host: app.example.com
    backend: http://localhost:3000
    app_id: app-wiki

  - host: "*.example.com"           # wildcard support
    backend: http://localhost:3000
```

## Security

| Layer | What it protects against |
|-------|------------------------|
| **hyper** (HTTP parser) | Request smuggling, header injection, HTTP/2 violations |
| **SM VALIDATED state** | Host header poisoning, path traversal, oversized requests |
| **Auth check** | Unauthenticated access (fail-closed: volta down → 502) |
| **Response strip** | Backend X-Volta-* header forgery (headers stripped from response) |

## Architecture

```
┌────────────────────────────────────────────┐
│  tower::ServiceBuilder                     │
│    TraceLayer → RateLimitLayer → Timeout   │
├────────────────────────────────────────────┤
│  ProxyService (SM lifecycle)               │
│                                            │
│  Sync judgment:          Async I/O:        │
│    RECEIVED → VALIDATED    (nothing)       │
│    VALIDATED → ROUTED      (nothing)       │
│    ROUTED → [External]     volta HTTP call │
│    AUTH_CHECKED → [Ext]    backend forward │
│    FORWARDED → COMPLETED   (nothing)       │
│                                            │
│  SM is sync (~2μs). I/O is async (hyper).  │
│  Separation of concerns.                   │
├────────────────────────────────────────────┤
│  hyper (HTTP) + tokio (async runtime)      │
└────────────────────────────────────────────┘
```

The SM pattern comes from [tramli](https://github.com/opaopa6969/tramli) — a constrained flow engine where invalid transitions cannot exist.

## vs Traefik

| | volta-gateway | Traefik |
|---|---|---|
| Auth latency | 0.5-1ms (localhost) | 4-10ms (ForwardAuth, 2 hops) |
| Request visibility | Per-step SM transitions | "request in, response out" |
| Config | 1 YAML file | Docker labels + traefik.yml + middleware chain |
| Routing | Host → backend (wildcard) | Labels, file, Consul, etcd, ... |
| Debug | SM state log shows exact failure point | Read Traefik debug logs, good luck |

## Development with tramli

volta-gateway uses [tramli](https://github.com/opaopa6969/tramli) (`tramli = "0.1"` on [crates.io](https://crates.io/crates/tramli)) as its state machine engine.

### Why tramli?

The proxy's request lifecycle is defined in **8 lines of Rust**:

```rust
Builder::new("proxy")
    .from(Received).auto(Validated, RequestValidator { routing })
    .from(Validated).auto(Routed, RoutingResolver { routing })
    .from(Routed).external(AuthChecked, AuthGuard)
    .from(AuthChecked).external(Forwarded, ForwardGuard)
    .from(Forwarded).auto(Completed, CompletionProcessor)
    .on_any_error(BadGateway)
    .build()  // ← 8-item validation here
```

`build()` validates at startup:
1. All states reachable from initial
2. Path to terminal exists
3. Auto/Branch transitions form a DAG
4. At most 1 External per state
5. All branch targets defined
6. requires/produces chain integrity
7. No transitions from terminal states
8. Initial state exists

**If `build()` passes, the flow is structurally correct.** No runtime state machine bugs.

### The B-pattern: sync SM + async I/O

tramli is intentionally synchronous (~2μs per request). Async I/O happens outside:

```rust
// 1. Sync: SM judgment (~1μs)
let flow_id = engine.start_flow(&def, &id, initial_data)?;
// auto-chains: RECEIVED → VALIDATED → ROUTED (stops at External)

// 2. Async: volta auth check (~500μs)
let auth = volta_client.check_auth(&req).await;

// 3. Sync: SM judgment (~300ns)
engine.resume_and_execute(&flow_id, auth_data)?;
// AUTH_CHECKED (stops at next External)

// 4. Async: backend forward (~1-50ms)
let resp = backend.forward(&req).await;

// 5. Sync: SM judgment (~300ns)
engine.resume_and_execute(&flow_id, resp_data)?;
// FORWARDED → COMPLETED (terminal)
```

SM never blocks. I/O never enters SM. Clean separation.

### Adding a new processor

1. Define a `struct` implementing `StateProcessor<ProxyState>`
2. Declare `requires()` (input types) and `produces()` (output types)
3. Add `.from(X).auto(Y, MyProcessor)` to the Builder
4. `build()` validates the entire chain — if it compiles and `build()` passes, it works

```rust
struct MyRateLimiter;

impl StateProcessor<ProxyState> for MyRateLimiter {
    fn name(&self) -> &str { "RateLimiter" }
    fn requires(&self) -> Vec<TypeId> { vec![TypeId::of::<RequestData>()] }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let req = ctx.get::<RequestData>()?;
        // ... rate limit check ...
        Ok(())
    }
}
```

See [tramli docs](https://github.com/opaopa6969/tramli) for the full API. The [user review](https://github.com/opaopa6969/tramli/blob/main/docs/review-volta-gateway.md) covers real-world experience building this proxy.

## Requirements

- Rust 1.75+ (edition 2021)
- volta-auth-proxy running (for auth checks)
- Backend apps running

## License

MIT
