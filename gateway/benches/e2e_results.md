# E2E Benchmark Results

> Date: 2026-04-07
> Machine: Linux 6.6.87 (WSL2), x86_64
> Tool: oha v1.14.0
> Build: cargo build --release

## Setup

- Mock backend: hyper echo server (200 + 40 bytes JSON)
- Mock volta-auth: hyper (200 + X-Volta-User-Id, always approve)
- volta-gateway: release build, RUST_LOG=error

## Results

### Baseline: Direct to mock backend (no proxy)

```
Requests/sec: 4,719
Average:      0.209 ms
p50:          0.203 ms
p99:          0.298 ms
p99.9:        0.380 ms
```

### volta-gateway (proxy + auth + SM)

```
Requests/sec: 2,600 (single connection)
Average:      0.380 ms
p50:          0.243 ms
p99:          1.156 ms
p99.9:        1.861 ms
```

### Proxy overhead

```
p50 overhead:  0.243 - 0.203 = 0.040 ms (40 μs)
p99 overhead:  1.156 - 0.298 = 0.858 ms
avg overhead:  0.380 - 0.209 = 0.171 ms (171 μs)
```

### Breakdown (criterion micro-benchmarks)

| Component | Latency |
|-----------|---------|
| SM start_flow | 707 ns |
| SM full lifecycle (start + 2x resume) | 1.69 μs |
| Routing lookup (exact) | 11 ns |
| Routing lookup (wildcard) | 61 ns |
| Compression check | 5 ns |

### Analysis

- **SM overhead is negligible**: 1.69μs out of 171μs avg proxy overhead = ~1%
- **Auth round-trip dominates**: localhost HTTP to mock auth ≈ 100-150μs
- **Proxy p50 = 0.243ms** — well below the claimed "0.5-1ms auth latency"
- **vs Traefik ForwardAuth (4-10ms)**: volta-gateway's overhead is 0.17ms avg.
  Even accounting for the fact that Traefik's 4-10ms includes non-localhost auth,
  volta-gateway's localhost auth is ~20-60x faster than remote ForwardAuth.

### Fair comparison note

The "5-10x faster" claim in the paper compares volta-gateway (localhost auth)
vs Traefik (remote auth). For a fair comparison, Traefik + localhost ForwardAuth
should be benchmarked. Estimated Traefik + localhost overhead: 1-3ms (Go HTTP
client + middleware chain + ForwardAuth subrequest). This would make
volta-gateway ~5-15x faster in same-condition comparison, primarily due to:
1. Rust's hyper being faster than Go's net/http for the proxy hop
2. Connection pool reuse (64 idle connections)
3. No middleware chain overhead (direct SM dispatch)

## Traefik Same-Condition Comparison (GW-52)

Both using localhost auth (same mock_auth on port 17070), same mock_backend.
Traefik v3.4 in Docker, ForwardAuth middleware. volta-gateway native release build.
oha -n 500 -c 1 (single connection, no rate limiter interference).

| Metric | volta-gateway | Traefik + ForwardAuth | Ratio |
|--------|--------------|----------------------|-------|
| **p50** | **0.252 ms** | **1.673 ms** | **6.6x faster** |
| avg | 0.395 ms | 1.777 ms | 4.5x faster |
| p95 | 1.060 ms | 2.273 ms | 2.1x faster |
| p99 | 1.235 ms | 2.373 ms | 1.9x faster |
| req/sec | 2,501 | 561 | 4.5x higher |

### Analysis

The "5-10x faster" claim is validated at p50 (6.6x). The advantage narrows
at higher percentiles (1.9x at p99) because tail latency is dominated by
OS scheduling and TCP stack overhead, not proxy implementation.

Sources of volta-gateway's advantage:
1. Rust hyper HTTP client vs Go net/http (less overhead per hop)
2. Connection pool with 64 idle connections (Traefik default: 200, but Go's
   pool has higher per-connection overhead)
3. Direct SM dispatch vs Traefik's middleware chain (entrypoint → router →
   middleware → ForwardAuth → middleware → service)
4. No Docker networking overhead (volta-gateway runs native)

Note: Traefik runs in Docker which adds ~0.1-0.3ms of networking overhead
via the Docker bridge. A native Traefik binary would be slightly faster,
but the Docker deployment is the typical production setup.

## Limitations

- Single connection benchmark (rate limiter prevents high concurrency testing
  without config change — rate_limit params are hardcoded in ProxyService::new)
- Mock auth does zero work (real volta-auth-proxy adds session validation time)
- WSL2 environment (not bare metal)
