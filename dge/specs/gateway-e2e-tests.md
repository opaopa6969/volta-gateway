# Gateway E2E Tests — 追加ケース

> Status: Implementing
> Date: 2026-04-09

## 既存テスト (5件)

1. proxy_forwards_to_backend — 正常転送 + X-Volta-* strip + x-request-id
2. proxy_returns_403_on_auth_denied — 403
3. proxy_returns_502_on_backend_down — 502
4. proxy_cors_preflight_returns_204 — CORS OPTIONS
5. proxy_rate_limit_returns_429 — レート制限

## 追加テスト (3件)

6. **proxy_public_route_skips_auth** — `public: true` でauth スキップ
7. **proxy_unknown_host_returns_400** — routing にないホスト → 400
8. **proxy_auth_bypass_path** — `auth_bypass_paths` 一致 → auth スキップ
