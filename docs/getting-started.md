[日本語版はこちら / Japanese](getting-started-ja.md)

# Getting Started with volta-gateway

This guide walks you from `git clone` to a working request through the
gateway. The whole loop fits in one terminal, and it covers three layouts:

1. **Gateway + Java auth-proxy** (legacy topology).
2. **Gateway + Rust auth-server** (replacement topology — recommended).
3. **Unified `volta-bin`** (gateway + auth-core in-process, no HTTP roundtrip).

## 0. Prerequisites

- Rust 1.75+ (edition 2021)
- PostgreSQL 13+ (for auth-core features)
- Docker (optional — for integration tests and the `volta-auth-proxy` sidecar)
- A backend HTTP service to route to. If you don't have one, use the
  `mock_backend` example shipped with the repo.

## 1. Clone and build

```bash
git clone https://github.com/opaopa6969/volta-gateway
cd volta-gateway
cargo build --workspace --release
```

The workspace has five crates (`gateway`, `auth-core`, `auth-server`,
`volta-bin`, `tools/traefik-to-volta`). Check
[`docs/architecture.md`](architecture.md) before editing any of them.

## 2. Minimum config

Create `my-config.yaml`:

```yaml
server:
  port: 8080

auth:
  volta_url: http://localhost:7070   # auth-server (or Java auth-proxy)
  timeout_ms: 500                    # fail-closed: auth down → 502

routing:
  - host: app.localhost
    backend: http://localhost:3000
    app_id: my-app
```

Full field reference: [`volta-gateway.full.yaml`](../volta-gateway.full.yaml).

## 3. Spin up a mock backend + mock auth (no DB)

For a pure smoke test, you don't need PostgreSQL. The `gateway` crate ships
two examples:

```bash
# Terminal 1 — mock backend on :3000 (returns {"ok": true})
cargo run --release -p volta-gateway --example mock_backend

# Terminal 2 — mock auth on :7070 (accepts every request)
cargo run --release -p volta-gateway --example mock_auth

# Terminal 3 — gateway on :8080
cargo run --release -p volta-gateway -- my-config.yaml
```

Check it works:

```bash
curl -H "Host: app.localhost" http://localhost:8080/api/hi
# => {"ok":true}
```

Each response carries `x-request-id` so you can trace it. The gateway logs
five transitions per request (Received → Validated → Routed → AuthChecked →
Forwarded → Completed) with `durationMicros` for each hop.

## 4. Swap to the real auth-server (Rust)

`auth-server` is the Java-parity Axum service (see [`parity.md`](parity.md)).
It needs PostgreSQL.

```bash
# Start Postgres
docker run --rm -d --name volta-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
export DATABASE_URL=postgres://postgres:postgres@localhost/postgres
export JWT_SECRET="$(openssl rand -hex 32)"

# Run auth-server on :7070 (same URL the gateway points to)
cargo run --release -p volta-auth-server

# Gateway unchanged — still points at http://localhost:7070
cargo run --release -p volta-gateway -- my-config.yaml
```

Visit `http://localhost:8080/login` to kick off an OIDC flow. Configure the
IdP env vars (`IDP_PROVIDER`, `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`) as listed
in [`auth-server/README.md`](../auth-server/README.md).

## 5. Unified binary — zero auth hop

`volta-bin` bundles the gateway and `auth-core` into one process. Auth checks
become ~1 µs in-process function calls instead of a ~250 µs HTTP roundtrip.

```bash
cargo run --release -p volta-bin -- my-config.yaml
```

Enable in config:

```yaml
auth:
  jwt_secret: "${JWT_SECRET}"   # in-process JWT verification
  cookie_name: volta_session
```

This mode does **not** expose the 96 routes (login, MFA, etc.) — it only
*verifies* existing sessions. Pair it with an `auth-server` instance for the
full flow, or keep the Java sidecar during migration.

## 6. Public routes, CORS, load balancing

Public routes (webhooks, health probes):

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    auth_bypass_paths:
      - prefix: /webhooks/
      - prefix: /health
```

CORS is **deny-by-default** (DD-001). Opt in per route:

```yaml
routing:
  - host: app.localhost
    backend: http://localhost:3000
    cors_origins:
      - https://app.localhost
```

Weighted canary:

```yaml
routing:
  - host: app.localhost
    backends:
      - url: http://localhost:3000
        weight: 9    # 90%
      - url: http://localhost:3001
        weight: 1    # 10%
```

## 7. HTTPS with Let's Encrypt

TLS-ALPN-01:

```yaml
server:
  port: 8080
  force_https: true

tls:
  domains:
    - app.example.com
  contact_email: admin@example.com
  port: 443
  cache_dir: ./acme-cache
  staging: true   # switch to false in production
```

DNS-01 via Cloudflare (for wildcard certs):

```yaml
tls:
  domains:
    - "*.example.com"
  contact_email: admin@example.com
  dns01:
    cloudflare_api_token_env: CF_DNS_TOKEN
```

## 8. Config validation in CI

```bash
cargo run --release -p volta-gateway -- --validate my-config.yaml
```

Returns non-zero on any invalid route, unknown plugin, or missing backend.
Add it to your pipeline before deploy.

## 9. Hot reload

Zero-downtime route swap (`ArcSwap`):

```bash
kill -HUP $(pgrep volta-gateway)
# or
curl -X POST http://localhost:8080/admin/reload
```

## 10. Admin API

All localhost-only:

```bash
curl http://localhost:8080/admin/routes     # routing table
curl http://localhost:8080/admin/backends   # backend health
curl http://localhost:8080/admin/stats      # counters
curl http://localhost:8080/metrics          # Prometheus
```

## 11. Load test

```bash
# Simple smoke (hey or wrk)
hey -n 100000 -c 100 -host app.localhost http://localhost:8080/api/hi

# Benchmark script used for the README numbers
cargo bench -p volta-gateway --bench proxy_bench
```

See [`docs/benchmark-article.md`](benchmark-article.md) for the full
methodology and the 6.6x vs Traefik result.

## 12. What to read next

- [README](../README.md) — features and positioning
- [`docs/architecture.md`](architecture.md) — FlowEngine, routing, 5-merge router, plugins
- [`docs/parity.md`](parity.md) — Rust vs Java, route-by-route
- [`docs/migration-from-traefik.md`](migration-from-traefik.md) — migration guide
- [`docs/feedback.md`](feedback.md) — tramli upgrade loop (3.2 → 3.8)
- [Full YAML reference](../volta-gateway.full.yaml)
