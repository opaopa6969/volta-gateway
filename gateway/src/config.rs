use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct WeightedBackend {
    pub url: String,
    pub weight: u32,
}

// Support both "http://a" and {url: "http://a", weight: 90}
impl<'de> Deserialize<'de> for WeightedBackend {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum BackendEntry {
            Simple(String),
            Weighted { url: String, #[serde(default = "default_weight")] weight: u32 },
        }
        match BackendEntry::deserialize(deserializer)? {
            BackendEntry::Simple(url) => Ok(WeightedBackend { url, weight: 1 }),
            BackendEntry::Weighted { url, weight } => Ok(WeightedBackend { url, weight }),
        }
    }
}

fn default_weight() -> u32 { 1 }

fn deserialize_backends<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<WeightedBackend>, D::Error> {
    Vec::<WeightedBackend>::deserialize(deserializer)
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub routing: Vec<RouteEntry>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub backend_pool: BackendPoolConfig,
    #[serde(default)]
    pub healthcheck: HealthCheckConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    /// Directory containing custom error pages (e.g. 502.html, 403.html).
    /// Falls back to JSON if not set or file not found.
    #[serde(default)]
    pub error_pages_dir: Option<String>,
    /// TLS/ACME configuration. If set, enables HTTPS with Let's Encrypt.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// L4 (TCP/UDP) proxy entries. Each entry forwards a local port to a backend.
    #[serde(default)]
    pub l4_proxy: Vec<L4ProxyEntry>,
    /// Plugin configurations.
    #[serde(default)]
    pub plugins: Vec<crate::plugin::PluginConfig>,
    /// External config sources (services.json, Docker labels, HTTP polling).
    #[serde(default)]
    pub config_sources: Vec<crate::config_source::ConfigSourceEntry>,
    /// #39: Access log configuration.
    #[serde(default)]
    pub access_log: Option<AccessLogConfig>,
    /// #55: Tenancy configuration (Layer 2).
    #[serde(default)]
    pub tenancy: TenancyConfig,
    /// #55: Access control defaults (Layer 3).
    #[serde(default)]
    pub access: AccessConfig,
    /// #55: Binding configuration (Layer 4).
    #[serde(default)]
    pub binding: BindingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct L4ProxyEntry {
    /// Listen port
    pub listen_port: u16,
    /// Protocol: "tcp" or "udp"
    #[serde(default = "default_l4_proto")]
    pub protocol: String,
    /// Backend address (e.g. "10.0.0.5:5432")
    pub backend: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Domains for ACME certificate. Must match routing hosts.
    pub domains: Vec<String>,
    /// Contact email for Let's Encrypt (e.g. "mailto:admin@example.com")
    pub contact_email: String,
    /// HTTPS port (default: 443)
    #[serde(default = "default_tls_port")]
    pub port: u16,
    /// Cache directory for ACME certificates (default: "./acme-cache")
    #[serde(default = "default_acme_cache")]
    pub cache_dir: String,
    /// Use Let's Encrypt staging (default: false). Set to true for testing.
    #[serde(default)]
    pub staging: bool,
    /// ACME challenge type: "http-01" (default) or "dns-01".
    #[serde(default = "default_challenge")]
    pub challenge: String,
    /// DNS provider for DNS-01 challenge (e.g. "cloudflare").
    pub dns_provider: Option<String>,
    /// DNS provider API token (or use env: CF_DNS_API_TOKEN).
    pub dns_api_token: Option<String>,
    /// DNS zone ID for Cloudflare (or use env: CF_ZONE_ID).
    pub dns_zone_id: Option<String>,
}

fn default_challenge() -> String { "http-01".into() }

/// #39: Access log configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessLogConfig {
    #[serde(default)]
    pub enabled: bool,
    /// File path for access logs. None = stdout only.
    pub path: Option<String>,
    /// Log format: "json" (default) or "combined" (Apache-style).
    #[serde(default = "default_access_format")]
    pub format: String,
}

fn default_access_format() -> String { "json".into() }

// ─── #55: Config Schema v3 ─────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenancyConfig {
    #[serde(default = "default_tenancy_mode")]
    pub mode: String,
    #[serde(default = "default_creation_policy")]
    pub creation_policy: String,
    #[serde(default)]
    pub shadow_org: bool,
    #[serde(default = "default_max_orgs")]
    pub max_orgs_per_user: u32,
    #[serde(default = "default_org_display")]
    pub org_display_name: String,
    #[serde(default)]
    pub routing: TenantRouting,
}
fn default_tenancy_mode() -> String { "single".into() }
fn default_creation_policy() -> String { "disabled".into() }
fn default_max_orgs() -> u32 { 1 }
fn default_org_display() -> String { "Organization".into() }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TenantRouting {
    #[serde(default = "default_routing_mode")]
    pub mode: String,
    pub base_domain: Option<String>,
    #[serde(default = "default_slug_header")]
    pub slug_header: String,
    #[serde(default = "default_cookie_scope")]
    pub cookie_scope: String,
}
fn default_routing_mode() -> String { "none".into() }
fn default_slug_header() -> String { "X-Volta-Tenant-Slug".into() }
fn default_cookie_scope() -> String { "shared".into() }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccessConfig {
    #[serde(default = "default_visibility")]
    pub default_visibility: String,
    #[serde(default)]
    pub custom_roles: bool,
    #[serde(default = "default_actions")]
    pub available_actions: Vec<String>,
}
fn default_visibility() -> String { "all".into() }
fn default_actions() -> Vec<String> {
    ["view","open","deploy","terminal","config","admin","delete"].iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BindingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub datasource_types: Vec<String>,
    #[serde(default = "default_on_delete")]
    pub on_user_delete: String,
    #[serde(default = "default_retention")]
    pub retention_days: u32,
}
fn default_on_delete() -> String { "archive".into() }
fn default_retention() -> u32 { 90 }

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    /// Redirect HTTP to HTTPS (requires tls config). Default: false.
    #[serde(default)]
    pub force_https: bool,
    /// Trusted proxy CIDRs (e.g. Cloudflare IPs). When set, CF-Connecting-IP
    /// is used as client IP instead of X-Forwarded-For.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_volta_url")]
    pub volta_url: String,
    #[serde(default = "default_verify_path")]
    pub verify_path: String,
    #[serde(default = "default_auth_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_pool_max_idle")]
    pub pool_max_idle: usize,
    /// JWT secret for in-process session verification (DD-005 Phase 0).
    /// If set, gateway verifies session JWT locally before falling back to HTTP.
    #[serde(default)]
    pub jwt_secret: Option<String>,
    /// Session cookie name (default: __volta_session).
    #[serde(default = "default_cookie_name")]
    pub cookie_name: Option<String>,
    /// Public-facing base URL of the auth proxy (e.g. https://auth.example.com).
    /// Redirects from auth-proxy to this origin are allowed through sanitize_redirect.
    #[serde(default)]
    pub auth_public_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteEntry {
    pub host: String,
    /// Single backend (simple)
    #[serde(default)]
    pub backend: Option<String>,
    /// Multiple backends for load balancing.
    /// Supports both simple strings and weighted objects:
    ///   backends: ["http://a:3000", "http://b:3000"]           # equal weight
    ///   backends: [{url: "http://a:3000", weight: 90}, ...]    # weighted
    #[serde(default, deserialize_with = "deserialize_backends")]
    pub backends: Vec<WeightedBackend>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
    /// Allowed CORS origins for this route. Empty = no CORS headers.
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Path prefix for route matching (e.g. "/v1/"). Empty = match all paths.
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Strip this prefix before forwarding to backend (e.g. "/v1" → "/users").
    #[serde(default)]
    pub strip_prefix: Option<String>,
    /// Add this prefix before forwarding to backend (e.g. "/" → "/app/").
    #[serde(default)]
    pub add_prefix: Option<String>,
    /// Request header manipulation.
    #[serde(default)]
    pub request_headers: Option<HeaderManipulation>,
    /// Response header manipulation.
    #[serde(default)]
    pub response_headers: Option<HeaderManipulation>,
    /// Geo-based access control using CF-IPCountry header.
    #[serde(default)]
    pub geo_allowlist: Vec<String>,
    #[serde(default)]
    pub geo_denylist: Vec<String>,
    /// Skip auth entirely for this route (e.g. auth server itself, public docs).
    #[serde(default)]
    pub public: bool,
    /// Paths that bypass auth (e.g. Slack webhooks). Optional backend override.
    #[serde(default)]
    pub auth_bypass_paths: Vec<BypassPath>,
    /// Traffic mirroring — copy requests to shadow backend (fire-and-forget).
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,
    /// Per-route request timeout in seconds (overrides server.request_timeout_secs).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Response cache configuration.
    #[serde(default)]
    pub cache: Option<crate::cache::CacheConfig>,
    /// mTLS configuration for backend connections.
    #[serde(default)]
    pub backend_tls: Option<crate::mtls::BackendTlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderManipulation {
    #[serde(default)]
    pub add: HashMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MirrorConfig {
    /// Shadow backend URL
    pub backend: String,
    /// Sample rate 0.0-1.0 (1.0 = mirror all requests)
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BypassPath {
    pub prefix: String,
    /// Optional backend override for this bypass path.
    #[serde(default)]
    pub backend: Option<String>,
}

impl RouteEntry {
    /// Get all backend URLs (merges `backend` and `backends`).
    pub fn all_backends(&self) -> Vec<String> {
        let mut result: Vec<String> = self.backends.iter().map(|b| b.url.clone()).collect();
        if let Some(ref b) = self.backend {
            if !result.contains(b) { result.insert(0, b.clone()); }
        }
        result
    }

    /// Get weights for backends (same order as all_backends).
    pub fn all_weights(&self) -> Vec<u32> {
        let mut weights: Vec<u32> = self.backends.iter().map(|b| b.weight).collect();
        if let Some(ref b) = self.backend {
            if !self.backends.iter().any(|wb| wb.url == *b) {
                weights.insert(0, 1); // single backend gets weight 1
            }
        }
        weights
    }
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct BackendPoolConfig {
    #[serde(default = "default_pool_idle")]
    pub max_idle_per_host: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct HealthCheckConfig {
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_hc_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl GatewayConfig {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: GatewayConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// PH2-4: Validate config at startup. Returns errors (not warnings).
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = vec![];
        if self.routing.is_empty() {
            errors.push("routing is empty — no requests will be served".into());
        }
        if self.server.port == 0 {
            errors.push("server.port must be > 0".into());
        }
        // Duplicate host check
        let mut hosts = std::collections::HashSet::new();
        for r in &self.routing {
            if !hosts.insert(&r.host) {
                errors.push(format!("duplicate routing host: {} — path_prefix based routing on same host is not yet supported. Use separate hosts or a single route with auth_bypass_paths.", r.host));
            }
        }
        // Validate IP allowlist entries are valid CIDR
        for r in &self.routing {
            for cidr in &r.ip_allowlist {
                if cidr.parse::<ipnet::IpNet>().is_err() {
                    errors.push(format!("invalid CIDR in ip_allowlist for {}: {}", r.host, cidr));
                }
            }
        }
        // Validate TLS config
        if let Some(ref tls) = self.tls {
            if tls.domains.is_empty() {
                errors.push("tls.domains is empty — no certificates will be issued".into());
            }
            if tls.contact_email.is_empty() {
                errors.push("tls.contact_email is required for ACME".into());
            }
            if tls.port == 0 {
                errors.push("tls.port must be > 0".into());
            }
        }
        // Validate force_https requires TLS
        if self.server.force_https && self.tls.is_none() {
            errors.push("server.force_https requires tls config".into());
        }
        // Validate L4 proxy entries
        for (i, entry) in self.l4_proxy.iter().enumerate() {
            if entry.listen_port == 0 {
                errors.push(format!("l4_proxy[{}].listen_port must be > 0", i));
            }
            if entry.backend.is_empty() {
                errors.push(format!("l4_proxy[{}].backend is empty", i));
            }
            if entry.protocol != "tcp" && entry.protocol != "udp" {
                errors.push(format!("l4_proxy[{}].protocol must be 'tcp' or 'udp', got '{}'", i, entry.protocol));
            }
        }
        // Validate no backend configured
        for r in &self.routing {
            if r.all_backends().is_empty() {
                errors.push(format!("routing host '{}' has no backends", r.host));
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Build routing table: host → RouteInfo
    /// GW-45: host keys are lowercased for consistent lookup
    pub fn routing_table(&self) -> HashMap<String, crate::proxy::RouteInfo> {
        self.routing
            .iter()
            .map(|r| (r.host.to_lowercase(), crate::proxy::RouteInfo {
                backends: r.all_backends(),
                weights: r.all_weights(),
                app_id: r.app_id.clone(),
                public: r.public,
                bypass_paths: r.auth_bypass_paths.clone(),
                mirror: r.mirror.clone(),
                path_prefix: r.path_prefix.clone(),
                strip_prefix: r.strip_prefix.clone(),
                add_prefix: r.add_prefix.clone(),
                request_headers: r.request_headers.clone(),
                response_headers: r.response_headers.clone(),
                geo_allowlist: r.geo_allowlist.clone(),
                geo_denylist: r.geo_denylist.clone(),
                timeout_secs: r.timeout_secs,
                cache: r.cache.clone(),
                backend_tls: r.backend_tls.clone(),
            }))
            .collect()
    }

    /// Build CORS origins table: host → allowed origins
    /// GW-44: empty cors_origins = no CORS headers (not wildcard)
    pub fn cors_table(&self) -> HashMap<String, Vec<String>> {
        self.routing.iter()
            .filter(|r| !r.cors_origins.is_empty())
            .map(|r| (r.host.to_lowercase(), r.cors_origins.clone()))
            .collect()
    }

    /// Build IP allowlist: host → Vec<IpNet>
    pub fn ip_allowlist_table(&self) -> HashMap<String, Vec<ipnet::IpNet>> {
        self.routing.iter()
            .filter(|r| !r.ip_allowlist.is_empty())
            .map(|r| (
                r.host.to_lowercase(),
                r.ip_allowlist.iter().filter_map(|c| c.parse().ok()).collect(),
            ))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────

    fn make_route(host: &str, backend: &str) -> RouteEntry {
        RouteEntry {
            host: host.to_string(),
            backend: Some(backend.to_string()),
            backends: vec![],
            app_id: None,
            ip_allowlist: vec![],
            cors_origins: vec![],
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            public: false,
            auth_bypass_paths: vec![],
            mirror: None,
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        }
    }

    fn make_weighted_route(host: &str, backends: Vec<WeightedBackend>) -> RouteEntry {
        RouteEntry {
            host: host.to_string(),
            backend: None,
            backends,
            app_id: None,
            ip_allowlist: vec![],
            cors_origins: vec![],
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            public: false,
            auth_bypass_paths: vec![],
            mirror: None,
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        }
    }

    fn minimal_config_yaml(extra: &str) -> String {
        format!(
            r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://backend:3000"
{}
"#,
            extra
        )
    }

    fn parse_config(yaml: &str) -> GatewayConfig {
        serde_yaml::from_str(yaml).expect("yaml parse failed")
    }

    // ── RouteEntry::all_backends ─────────────────────────────────

    #[test]
    fn all_backends_single_backend_field() {
        let route = make_route("example.com", "http://backend:3000");
        assert_eq!(route.all_backends(), vec!["http://backend:3000"]);
    }

    #[test]
    fn all_backends_weighted_only() {
        let route = make_weighted_route(
            "example.com",
            vec![
                WeightedBackend { url: "http://a:3000".into(), weight: 90 },
                WeightedBackend { url: "http://b:3000".into(), weight: 10 },
            ],
        );
        assert_eq!(route.all_backends(), vec!["http://a:3000", "http://b:3000"]);
    }

    #[test]
    fn all_backends_single_not_duplicated_when_also_in_backends() {
        // backend field url already appears in backends — should not duplicate
        let route = RouteEntry {
            host: "example.com".into(),
            backend: Some("http://a:3000".into()),
            backends: vec![WeightedBackend { url: "http://a:3000".into(), weight: 90 }],
            app_id: None,
            ip_allowlist: vec![],
            cors_origins: vec![],
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            public: false,
            auth_bypass_paths: vec![],
            mirror: None,
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        };
        // should appear exactly once
        assert_eq!(route.all_backends().len(), 1);
    }

    #[test]
    fn all_backends_empty_when_none_configured() {
        let route = RouteEntry {
            host: "example.com".into(),
            backend: None,
            backends: vec![],
            app_id: None,
            ip_allowlist: vec![],
            cors_origins: vec![],
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            public: false,
            auth_bypass_paths: vec![],
            mirror: None,
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        };
        assert!(route.all_backends().is_empty());
    }

    // ── RouteEntry::all_weights ──────────────────────────────────

    #[test]
    fn all_weights_single_backend_gets_weight_one() {
        let route = make_route("example.com", "http://backend:3000");
        assert_eq!(route.all_weights(), vec![1u32]);
    }

    #[test]
    fn all_weights_preserves_weighted_values() {
        let route = make_weighted_route(
            "example.com",
            vec![
                WeightedBackend { url: "http://a:3000".into(), weight: 70 },
                WeightedBackend { url: "http://b:3000".into(), weight: 30 },
            ],
        );
        assert_eq!(route.all_weights(), vec![70u32, 30u32]);
    }

    // ── GatewayConfig::validate ──────────────────────────────────

    #[test]
    fn validate_passes_for_minimal_valid_config() {
        let cfg = parse_config(&minimal_config_yaml(""));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_fails_when_routing_is_empty() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing: []
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("routing is empty")));
    }

    #[test]
    fn validate_fails_for_duplicate_hosts() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
  - host: "example.com"
    backend: "http://b:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("duplicate routing host")));
    }

    #[test]
    fn validate_fails_for_invalid_cidr_in_ip_allowlist() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
    ip_allowlist:
      - "not-a-cidr"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("invalid CIDR")));
    }

    #[test]
    fn validate_fails_when_route_has_no_backend() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("no backends")));
    }

    #[test]
    fn validate_fails_force_https_without_tls() {
        let yaml = r#"
server:
  port: 8080
  force_https: true
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("force_https")));
    }

    #[test]
    fn validate_fails_for_invalid_l4_proxy_protocol() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
l4_proxy:
  - listen_port: 5432
    backend: "10.0.0.5:5432"
    protocol: "sctp"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let errs = cfg.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("protocol must be 'tcp' or 'udp'")));
    }

    // ── cors_table / ip_allowlist_table ──────────────────────────

    #[test]
    fn cors_table_excludes_routes_without_cors_origins() {
        let cfg = parse_config(&minimal_config_yaml(""));
        let table = cfg.cors_table();
        // minimal config has no cors_origins → table should be empty
        assert!(table.is_empty());
    }

    #[test]
    fn cors_table_includes_routes_with_cors_origins() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "api.example.com"
    backend: "http://a:3000"
    cors_origins:
      - "https://app.example.com"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let table = cfg.cors_table();
        assert!(table.contains_key("api.example.com"));
        assert_eq!(table["api.example.com"], vec!["https://app.example.com"]);
    }

    #[test]
    fn ip_allowlist_table_parses_valid_cidr() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "internal.example.com"
    backend: "http://a:3000"
    ip_allowlist:
      - "10.0.0.0/8"
      - "192.168.1.0/24"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let table = cfg.ip_allowlist_table();
        assert!(table.contains_key("internal.example.com"));
        assert_eq!(table["internal.example.com"].len(), 2);
    }

    // ── Default field values ─────────────────────────────────────

    #[test]
    fn server_defaults_are_applied_when_fields_absent() {
        let yaml = r#"
server: {}
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.server.read_timeout_secs, 10);
        assert_eq!(cfg.server.request_timeout_secs, 30);
        assert!(!cfg.server.force_https);
    }

    #[test]
    fn rate_limit_defaults_are_applied() {
        let cfg = parse_config(&minimal_config_yaml(""));
        assert_eq!(cfg.rate_limit.requests_per_second, 1000);
        assert_eq!(cfg.rate_limit.per_ip_rps, 100);
    }

    #[test]
    fn tenancy_defaults_are_applied_when_section_present() {
        // When tenancy: {} is present in YAML, per-field serde defaults fire.
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
tenancy: {}
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.tenancy.mode, "single");
        assert_eq!(cfg.tenancy.creation_policy, "disabled");
        assert_eq!(cfg.tenancy.max_orgs_per_user, 1);
    }

    #[test]
    fn binding_defaults_are_applied_when_section_present() {
        // When binding: {} is present in YAML, per-field serde defaults fire.
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
binding: {}
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!cfg.binding.enabled);
        assert_eq!(cfg.binding.on_user_delete, "archive");
        assert_eq!(cfg.binding.retention_days, 90);
    }

    // ── WeightedBackend deserialization ──────────────────────────

    #[test]
    fn weighted_backend_simple_string_gets_weight_one() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backends:
      - "http://a:3000"
      - "http://b:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let route = &cfg.routing[0];
        assert_eq!(route.backends.len(), 2);
        assert_eq!(route.backends[0].weight, 1);
        assert_eq!(route.backends[1].weight, 1);
    }

    #[test]
    fn weighted_backend_explicit_weight_is_preserved() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backends:
      - url: "http://a:3000"
        weight: 80
      - url: "http://b:3000"
        weight: 20
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let route = &cfg.routing[0];
        assert_eq!(route.backends[0].weight, 80);
        assert_eq!(route.backends[1].weight, 20);
    }
}

fn default_port() -> u16 { 8080 }
fn default_read_timeout() -> u64 { 10 }
fn default_request_timeout() -> u64 { 30 }
fn default_volta_url() -> String { "http://localhost:7070".into() }
fn default_verify_path() -> String { "/auth/verify".into() }
fn default_auth_timeout() -> u64 { 500 }
fn default_pool_max_idle() -> usize { 32 }
fn default_cookie_name() -> Option<String> { Some("__volta_session".into()) }
fn default_rps() -> u32 { 1000 }
fn default_per_ip_rps() -> u32 { 100 }
fn default_pool_idle() -> usize { 64 }
fn default_idle_timeout() -> u64 { 90 }
fn default_hc_interval() -> u64 { 30 }
fn default_hc_path() -> String { "/healthz".into() }
fn default_log_level() -> String { "info".into() }
fn default_log_format() -> String { "json".into() }
fn default_tls_port() -> u16 { 443 }
fn default_acme_cache() -> String { "./acme-cache".into() }
fn default_l4_proto() -> String { "tcp".into() }
fn default_sample_rate() -> f64 { 1.0 }

impl Default for RateLimitConfig {
    fn default() -> Self { Self { requests_per_second: default_rps(), per_ip_rps: default_per_ip_rps() } }
}
impl Default for BackendPoolConfig {
    fn default() -> Self { Self { max_idle_per_host: default_pool_idle(), idle_timeout_secs: default_idle_timeout() } }
}
impl Default for HealthCheckConfig {
    fn default() -> Self { Self { interval_secs: default_hc_interval(), path: default_hc_path() } }
}
impl Default for LoggingConfig {
    fn default() -> Self { Self { level: default_log_level(), format: default_log_format() } }
}
