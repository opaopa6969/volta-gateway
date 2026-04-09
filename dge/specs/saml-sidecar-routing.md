# SAML Sidecar Routing (DD-005)

> Status: Implementing
> Date: 2026-04-09
> Ref: DD-005 (Java→Rust 段階的移行)

## 概要

SAML 認証パスは Java sidecar (volta-auth-proxy) に転送する。
Rust での SAML 実装 (samael) は未成熟なため、OpenSAML (Java, 15年の実績) を維持。

## 設計

### routing config

```yaml
routing:
  # SAML callback/metadata は Java sidecar に転送
  - host: auth.example.com
    path_prefix: /saml/
    backend: http://localhost:7070   # volta-auth-proxy (Java)
    public: true                      # SAML endpoints are pre-auth
    app_id: saml-sidecar

  # SAML IdP metadata endpoint
  - host: auth.example.com
    path_prefix: /auth/saml/
    backend: http://localhost:7070
    public: true
    app_id: saml-sidecar
```

### config.rs 拡張

新しい config フィールドは不要。既存の `path_prefix` + `public: true` で
SAML パスを Java sidecar に転送できる。

### 必要な作業

1. SAML sidecar routing の設定例 (example config)
2. docs/HANDOFF.md に SAML routing パターン記載

## サンプル config

`volta-gateway.saml.yaml` に SAML sidecar routing example を追加。
