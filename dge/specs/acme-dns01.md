# ACME DNS-01 Challenge Support

> Status: Implementing (Phase 1: Cloudflare provider + config)
> Date: 2026-04-09

## 概要

wildcard 証明書 (`*.example.com`) には DNS-01 challenge が必要。
現在の `rustls-acme` は HTTP-01 のみ対応。DNS-01 を追加実装。

## 課題

`rustls-acme` は HTTP-01 challenge にフォーカスしており、DNS-01 をサポートしない。
完全な DNS-01 フローには `instant-acme` (低レベル ACME client) が必要だが、
rustls-acme との共存は複雑。

## Phase 1 (今回): Cloudflare DNS provider + config 拡張

### TlsConfig 拡張

```yaml
tls:
  domains: ["*.example.com", "example.com"]
  contact_email: admin@example.com
  challenge: dns-01           # "http-01" (default) or "dns-01"
  dns_provider: cloudflare    # DNS provider
  dns_api_token: "cf-token"   # Provider API token (or env: CF_DNS_API_TOKEN)
  dns_zone_id: "zone-id"      # Cloudflare zone ID (or env: CF_ZONE_ID)
```

### Cloudflare DNS Record Manager

```rust
pub struct CloudflareDns {
    api_token: String,
    zone_id: String,
    http: reqwest::Client,
}

impl CloudflareDns {
    pub async fn create_txt_record(domain: &str, value: &str) -> Result<String>;
    pub async fn delete_txt_record(record_id: &str) -> Result<()>;
}
```

### コンポーネント

- `gateway/src/dns01.rs` — Cloudflare DNS record management
- `config.rs` — TlsConfig 拡張 (challenge, dns_provider, dns_api_token, dns_zone_id)

## Phase 2 (後日): Full ACME DNS-01 flow

- `instant-acme` crate 追加
- ACME order → DNS-01 challenge → TXT record 作成 → 検証 → cert download
- rustls へ cert ロード
- cert renewal scheduler
