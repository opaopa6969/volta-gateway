[日本語版](migration-from-traefik-ja.md)

# Migration Guide: Traefik → volta-gateway

## Overview

volta-gateway replaces Traefik as the reverse proxy for volta-auth-proxy. This guide maps Traefik concepts to volta-gateway equivalents.

## Architecture Change

```
Before:
  Client → CF → Traefik → volta (ForwardAuth middleware) → App
                         → App (direct)

After:
  Client → CF → volta-gateway → volta (localhost /auth/verify) → App
```

Traefik's ForwardAuth middleware (2 HTTP round-trips, 4-10ms) is replaced by volta-gateway's built-in auth check (1 localhost call, 0.5-1ms).

## Concept Mapping

| Traefik | volta-gateway | Notes |
|---------|---------------|-------|
| `traefik.yml` | `volta-gateway.yaml` | Single file for everything |
| Docker labels | `routing:` section | No Docker dependency |
| Middleware chain | SM processors | Structural, not configurable chain |
| ForwardAuth middleware | Built-in auth (localhost) | No extra HTTP hop |
| `entryPoints` | `server.port` | One port |
| Let's Encrypt (ACME) | Cloudflare (TLS termination) | CF handles certs |
| Dashboard (`/api/`) | `/metrics` + `/healthz` | Prometheus-compatible |
| Rate limiting middleware | Built-in per-IP rate limiter | Config in YAML |
| IP whitelist middleware | `ip_allowlist` per route | CIDR support |

## Config Translation

### Traefik Docker Labels

```yaml
# Traefik (docker-compose labels)
services:
  app-wiki:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.wiki.rule=Host(`wiki.example.com`)"
      - "traefik.http.routers.wiki.middlewares=volta-auth@docker"
      - "traefik.http.services.wiki.loadbalancer.server.port=3000"
      - "traefik.http.routers.wiki.tls.certresolver=letsencrypt"

  app-admin:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.admin.rule=Host(`admin.example.com`)"
      - "traefik.http.routers.admin.middlewares=volta-auth@docker"
      - "traefik.http.services.admin.loadbalancer.server.port=3001"

  # ForwardAuth middleware
  volta-auth:
    labels:
      - "traefik.http.middlewares.volta-auth.forwardauth.address=http://volta:7070/auth/verify"
      - "traefik.http.middlewares.volta-auth.forwardauth.authResponseHeaders=X-Volta-User-Id,X-Volta-Email,X-Volta-Tenant-Id,X-Volta-Roles,X-Volta-JWT"
```

### volta-gateway Equivalent

```yaml
# volta-gateway.yaml
server:
  port: 8080

auth:
  volta_url: http://localhost:7070
  verify_path: /auth/verify
  timeout_ms: 500

routing:
  - host: wiki.example.com
    backend: http://localhost:3000
    app_id: app-wiki

  - host: admin.example.com
    backend: http://localhost:3001
    app_id: app-admin
    ip_allowlist:
      - 10.0.0.0/8

rate_limit:
  requests_per_second: 1000
  per_ip_rps: 100
```

**Key differences:**
- No Docker labels needed — routing is in YAML
- Auth is automatic for all routes — no middleware chain
- X-Volta-* headers are forwarded automatically
- TLS is handled by Cloudflare, not the proxy

## Step-by-Step Migration

### 1. Install volta-gateway

```bash
git clone https://github.com/opaopa6969/volta-gateway
cd volta-gateway
cargo build --release
```

### 2. Create config from Traefik labels

For each Traefik router, create a routing entry:

```
traefik.http.routers.NAME.rule=Host(`HOST`)
traefik.http.services.NAME.loadbalancer.server.port=PORT
→
routing:
  - host: HOST
    backend: http://localhost:PORT
```

### 3. Update Cloudflare

Point CF origin to volta-gateway's port (default 8080) instead of Traefik's port (default 80/443).

### 4. Test

```bash
# Start volta-gateway
./target/release/volta-gateway volta-gateway.yaml

# Test health
curl http://localhost:8080/healthz

# Test auth redirect (unauthenticated)
curl -H "Host: wiki.example.com" http://localhost:8080/

# Check metrics
curl http://localhost:8080/metrics
```

### 5. Switch traffic

Update CF or DNS to point to volta-gateway. Keep Traefik running as fallback until confirmed stable.

### 6. Remove Traefik

Once stable, remove Traefik from docker-compose.

## What You Lose

| Traefik feature | Status in volta-gateway |
|----------------|------------------------|
| Let's Encrypt ACME | Use Cloudflare (or Phase 3: rustls) |
| Load balancing | Phase N (single backend per route for now) |
| Circuit breaker | Phase N |
| WebSocket proxy | Phase N |
| gRPC proxy | Phase N |
| Dashboard UI | `/metrics` (Prometheus) + `/healthz` (JSON) |
| Consul/etcd discovery | YAML config (hot reload planned) |

## What You Gain

| Feature | Benefit |
|---------|---------|
| Auth latency | 4-10ms → 0.5-1ms (5-10x faster) |
| Request visibility | Per-step SM transition log |
| Security | SM structural validation + X-Volta-* stripping |
| Config simplicity | 1 YAML file, no Docker labels |
| Startup time | ~10ms (Rust binary) vs ~2s (Traefik) |
| Memory | ~5MB RSS vs ~50MB (Traefik) |
