use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
            Weighted {
                url: String,
                #[serde(default = "default_weight")]
                weight: u32,
            },
        }
        match BackendEntry::deserialize(deserializer)? {
            BackendEntry::Simple(url) => Ok(WeightedBackend { url, weight: 1 }),
            BackendEntry::Weighted { url, weight } => Ok(WeightedBackend { url, weight }),
        }
    }
}

// Serialize in the explicit weighted form {url, weight} (self-describing,
// round-trips through the untagged Deserialize above).
impl Serialize for WeightedBackend {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("WeightedBackend", 2)?;
        s.serialize_field("url", &self.url)?;
        s.serialize_field("weight", &self.weight)?;
        s.end()
    }
}

fn default_weight() -> u32 {
    1
}

fn deserialize_backends<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<WeightedBackend>, D::Error> {
    Vec::<WeightedBackend>::deserialize(deserializer)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// BT-SEC-7: Admin API authentication.
    #[serde(default)]
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct L4ProxyEntry {
    /// Listen port
    pub listen_port: u16,
    /// Protocol: "tcp" or "udp"
    #[serde(default = "default_l4_proto")]
    pub protocol: String,
    /// Backend address (e.g. "10.0.0.5:5432")
    pub backend: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
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

fn default_challenge() -> String {
    "http-01".into()
}

/// #39: Access log configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct AccessLogConfig {
    #[serde(default)]
    pub enabled: bool,
    /// File path for access logs. None = stdout only.
    pub path: Option<String>,
    /// Log format: "json" (default) or "combined" (Apache-style).
    #[serde(default = "default_access_format")]
    pub format: String,
}

fn default_access_format() -> String {
    "json".into()
}

// ─── #55: Config Schema v3 ─────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[allow(dead_code)]
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
fn default_tenancy_mode() -> String {
    "single".into()
}
fn default_creation_policy() -> String {
    "disabled".into()
}
fn default_max_orgs() -> u32 {
    1
}
fn default_org_display() -> String {
    "Organization".into()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[allow(dead_code)]
pub struct TenantRouting {
    #[serde(default = "default_routing_mode")]
    pub mode: String,
    pub base_domain: Option<String>,
    #[serde(default = "default_slug_header")]
    pub slug_header: String,
    #[serde(default = "default_cookie_scope")]
    pub cookie_scope: String,
}
fn default_routing_mode() -> String {
    "none".into()
}
fn default_slug_header() -> String {
    "X-Volta-Tenant-Slug".into()
}
fn default_cookie_scope() -> String {
    "shared".into()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[allow(dead_code)]
pub struct AccessConfig {
    #[serde(default = "default_visibility")]
    pub default_visibility: String,
    #[serde(default)]
    pub custom_roles: bool,
    #[serde(default = "default_actions")]
    pub available_actions: Vec<String>,
}
fn default_visibility() -> String {
    "all".into()
}
fn default_actions() -> Vec<String> {
    [
        "view", "open", "deploy", "terminal", "config", "admin", "delete",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[allow(dead_code)]
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
fn default_on_delete() -> String {
    "archive".into()
}
fn default_retention() -> u32 {
    90
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    /// Graceful drain timeout: on SIGTERM/Ctrl+C, stop accepting new
    /// connections and wait up to this many seconds for in-flight requests to
    /// finish before forcing shutdown. Default: 30s.
    #[serde(default = "default_drain_timeout")]
    pub drain_timeout_secs: u64,

    /// SO_REUSEPORT を有効にする（#74 BT-HA-2）。
    ///
    /// 有効にすると **同じ :80 に複数プロセスが bind できる**。カーネルが接続を
    /// 分散するので、バイナリ更新は「新プロセスを上げる → 旧を drain して落とす」
    /// のローリングにでき、:80 が瞬断しない。
    ///
    /// 既定は **false**。既存のデプロイで有効になると、古いプロセスが残っている
    /// ことに気付かないまま新旧が同時に動く事故が起きうる（「再起動したのに古い
    /// 挙動のまま」の原因が読めなくなる）。運用手順を整えたうえで opt-in する。
    ///
    /// Linux / *BSD のみ。他プラットフォームでは無視して警告を出す。
    #[serde(default)]
    pub reuse_port: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_volta_url")]
    pub volta_url: String,
    #[serde(default = "default_verify_path")]
    pub verify_path: String,
    #[serde(default = "default_auth_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_pool_max_idle")]
    pub pool_max_idle: usize,
    /// JWT secret for explicit degraded-mode session verification (DD-005).
    /// This never replaces the normal online `/auth/verify` request.
    #[serde(default)]
    pub jwt_secret: Option<String>,
    /// Session cookie name (default: __volta_session).
    #[serde(default = "default_cookie_name")]
    pub cookie_name: Option<String>,
    /// Public-facing base URL of the auth proxy (e.g. https://auth.example.com).
    /// Redirects from auth-server to this origin are allowed through sanitize_redirect.
    #[serde(default)]
    pub auth_public_url: Option<String>,
    /// DD-005 縮退運転 (degraded mode): on auth-server failure, fall back to
    /// in-process JWT verification for requests that carry a still-valid session.
    /// Default false (fail-closed). The env var `VOLTA_AUTH_DEGRADED_MODE`
    /// (1/true/yes/on) overrides this YAML value, mirroring `admin.token`.
    #[serde(default)]
    pub degraded_mode: bool,
    /// RS256 public key for in-process verification. Either an inline PEM
    /// (`-----BEGIN PUBLIC KEY-----…`) or a path to a `.pem` file. auth-server
    /// issues RS256 tokens, so this (or `jwks_url`) is the production path.
    #[serde(default)]
    pub jwt_public_key_pem: Option<String>,
    /// JWKS endpoint URL for RS256 key discovery (e.g.
    /// `http://auth-server:7070/.well-known/jwks.json`). When set it takes
    /// precedence over `jwt_public_key_pem` and is refreshed on a TTL.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Expected `iss` claim for RS256 tokens (auth-server uses `volta-auth`).
    /// When unset, the issuer is not enforced.
    #[serde(default)]
    pub jwt_issuer: Option<String>,
    /// Expected `aud` claim for RS256 tokens (auth-server uses `volta-apps`).
    /// When unset, the audience is not enforced.
    #[serde(default)]
    pub jwt_audience: Option<String>,
    /// HMAC secret used to prove gateway origin to internal backends. The env
    /// `VOLTA_GATEWAY_ASSERTION_SECRET` overrides this value when non-empty.
    #[serde(default)]
    pub gateway_assertion_secret: Option<String>,
    /// Identifier emitted with assertions signed by the current key.
    #[serde(default)]
    pub gateway_assertion_key_id: Option<String>,
    /// Previous key accepted by consumers during a bounded rotation window.
    #[serde(default)]
    pub gateway_assertion_previous_key_id: Option<String>,
    #[serde(default)]
    pub gateway_assertion_previous_secret: Option<String>,
}

impl AuthConfig {
    /// Resolve the effective degraded-mode flag. `VOLTA_AUTH_DEGRADED_MODE`
    /// (1/true/yes/on, case-insensitive) overrides the YAML value when set to a
    /// non-empty value; otherwise the YAML `degraded_mode` is used.
    pub fn degraded_mode_enabled(&self) -> bool {
        if let Ok(raw) = std::env::var("VOLTA_AUTH_DEGRADED_MODE") {
            let v = raw.trim().to_ascii_lowercase();
            if !v.is_empty() {
                return matches!(v.as_str(), "1" | "true" | "yes" | "on");
            }
        }
        self.degraded_mode
    }

    pub fn effective_gateway_assertion_secret(&self) -> Option<String> {
        if let Ok(secret) = std::env::var("VOLTA_GATEWAY_ASSERTION_SECRET") {
            if !secret.is_empty() {
                return Some(secret);
            }
        }
        self.gateway_assertion_secret
            .as_ref()
            .filter(|secret| !secret.is_empty())
            .cloned()
    }

    pub fn effective_gateway_assertion_key_id(&self) -> String {
        std::env::var("VOLTA_GATEWAY_ASSERTION_KEY_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| {
                self.gateway_assertion_key_id
                    .as_ref()
                    .filter(|value| !value.is_empty())
                    .cloned()
            })
            .unwrap_or_else(|| crate::assertion::LEGACY_KEY_ID.into())
    }

    pub fn effective_gateway_assertion_previous(&self) -> (Option<String>, Option<String>) {
        let key_id = std::env::var("VOLTA_GATEWAY_ASSERTION_PREVIOUS_KEY_ID")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| self.gateway_assertion_previous_key_id.clone());
        let secret = std::env::var("VOLTA_GATEWAY_ASSERTION_PREVIOUS_SECRET")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| self.gateway_assertion_previous_secret.clone());
        (key_id, secret)
    }

    /// Resolve the RS256 public-key PEM bytes from `jwt_public_key_pem`, which
    /// may be either an inline PEM or a file path. Returns `None` when unset.
    pub fn resolve_public_key_pem(&self) -> Option<Result<Vec<u8>, String>> {
        let raw = self.jwt_public_key_pem.as_ref()?.trim().to_string();
        if raw.is_empty() {
            return None;
        }
        if raw.contains("-----BEGIN") {
            return Some(Ok(raw.into_bytes()));
        }
        // Treat as a filesystem path.
        Some(
            std::fs::read(&raw)
                .map_err(|e| format!("failed to read jwt_public_key_pem '{raw}': {e}")),
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

    /// このルートに必要な最低ロール（#58 / volta-platform#41）。
    ///
    /// `VIEWER` < `MEMBER` < `ADMIN` < `OWNER`。指定すると ForwardAuth に
    /// `X-Volta-Required-Role` を渡し、**auth-server がセッションのロールと
    /// 突き合わせて足りなければ 403** を返す。
    ///
    /// これまで services.json に `access.minRole` を書いても**誰も読んでいなかった**
    /// ため、「operator 限定にしたつもり」でも viewer でログインすれば通っていた。
    /// 判定を auth-server 側でやるのは、ロールの正はセッション（＝auth-server）に
    /// あるため。gateway は「何が必要か」を渡すだけにする。
    #[serde(default)]
    pub min_role: Option<String>,

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderManipulation {
    #[serde(default)]
    pub add: HashMap<String, String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MirrorConfig {
    /// Shadow backend URL
    pub backend: String,
    /// Sample rate 0.0-1.0 (1.0 = mirror all requests)
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
            if !result.contains(b) {
                result.insert(0, b.clone());
            }
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

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct BackendPoolConfig {
    #[serde(default = "default_pool_idle")]
    pub max_idle_per_host: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct HealthCheckConfig {
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_hc_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

/// BT-SEC-7: Admin API authentication config.
///
/// When `token` (or env `VOLTA_ADMIN_TOKEN`) is set, every `/admin/*` request
/// must carry a matching `Authorization: Bearer <token>` header. When unset,
/// the admin API stays loopback-only and all mutating (non-GET) endpoints are
/// rejected with 403.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[allow(dead_code)]
pub struct AdminConfig {
    /// Bearer token required for /admin/* requests. The env var
    /// `VOLTA_ADMIN_TOKEN` takes precedence over this YAML value.
    #[serde(default)]
    pub token: Option<String>,
}

impl AdminConfig {
    /// Resolve the effective admin token. `VOLTA_ADMIN_TOKEN` (if non-empty)
    /// overrides the YAML value. Returns `None` when neither is set.
    pub fn effective_token(&self) -> Option<String> {
        if let Ok(env_tok) = std::env::var("VOLTA_ADMIN_TOKEN") {
            if !env_tok.is_empty() {
                return Some(env_tok);
            }
        }
        self.token.as_ref().filter(|t| !t.is_empty()).cloned()
    }
}

impl GatewayConfig {
    /// Load + parse a config straight from a YAML file (no overlay applied).
    /// The gateway binary loads via [`config_overlay::ConfigStore`] instead, so
    /// this remains for library consumers and tests.
    #[allow(dead_code)]
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: GatewayConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// PH2-4: Validate config at startup. Returns errors (not warnings).
    /// SPEC §11.8 の終了コード (#95)。
    ///
    /// `--validate` は CI で使われるので、**何が悪かったのか**を終了コードで
    /// 区別できる必要がある。以前は 0/1 しか返さず、SPEC が定義する 2-5 に
    /// 相当する検査（flow build / backend URL / 未知 plugin / TLS 資格情報）が
    /// そもそも存在しなかった。
    pub const EXIT_SCHEMA: u8 = 1;
    /// proxy flow の build 失敗（tramli の不変条件違反）。main.rs が使う。
    pub const EXIT_FLOW_BUILD: u8 = 2;
    pub const EXIT_BACKEND_URL: u8 = 3;
    pub const EXIT_UNKNOWN_PLUGIN: u8 = 4;
    pub const EXIT_TLS_CREDENTIALS: u8 = 5;

    /// 文字列だけのエラー一覧（既存の呼び出し元との互換のため残す）。
    pub fn validate(&self) -> Result<(), Vec<String>> {
        self.validate_detailed()
            .map_err(|errs| errs.into_iter().map(|(_, msg)| msg).collect())
    }

    /// 終了コード付きの検証 (#95)。`(code, message)` を返す。
    pub fn validate_detailed(&self) -> Result<(), Vec<(u8, String)>> {
        let mut errors: Vec<(u8, String)> = vec![];
        if self.routing.is_empty() {
            errors.push((
                Self::EXIT_SCHEMA,
                "routing is empty — no requests will be served".into(),
            ));
        }
        if self.server.port == 0 {
            errors.push((Self::EXIT_SCHEMA, "server.port must be > 0".into()));
        }
        // Duplicate host check
        let mut hosts = std::collections::HashSet::new();
        for r in &self.routing {
            if !hosts.insert(&r.host) {
                errors.push((Self::EXIT_SCHEMA, format!("duplicate routing host: {} — path_prefix based routing on same host is not yet supported. Use separate hosts or a single route with auth_bypass_paths.", r.host)));
            }
        }
        // Validate IP allowlist entries are valid CIDR
        for r in &self.routing {
            for cidr in &r.ip_allowlist {
                if cidr.parse::<ipnet::IpNet>().is_err() {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!("invalid CIDR in ip_allowlist for {}: {}", r.host, cidr),
                    ));
                }
            }
        }
        // Validate TLS config
        if let Some(ref tls) = self.tls {
            if tls.domains.is_empty() {
                errors.push((
                    Self::EXIT_SCHEMA,
                    "tls.domains is empty — no certificates will be issued".into(),
                ));
            }
            if tls.contact_email.is_empty() {
                errors.push((
                    Self::EXIT_SCHEMA,
                    "tls.contact_email is required for ACME".into(),
                ));
            }
            if tls.port == 0 {
                errors.push((Self::EXIT_SCHEMA, "tls.port must be > 0".into()));
            }
        }
        // Validate force_https requires TLS
        if self.server.force_https && self.tls.is_none() {
            errors.push((
                Self::EXIT_SCHEMA,
                "server.force_https requires tls config".into(),
            ));
        }
        // Validate L4 proxy entries
        for (i, entry) in self.l4_proxy.iter().enumerate() {
            if entry.listen_port == 0 {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!("l4_proxy[{}].listen_port must be > 0", i),
                ));
            }
            if entry.backend.is_empty() {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!("l4_proxy[{}].backend is empty", i),
                ));
            }
            if entry.protocol != "tcp" && entry.protocol != "udp" {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!(
                        "l4_proxy[{}].protocol must be 'tcp' or 'udp', got '{}'",
                        i, entry.protocol
                    ),
                ));
            }
        }
        // Validate no backend configured
        for r in &self.routing {
            if r.all_backends().is_empty() {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!("routing host '{}' has no backends", r.host),
                ));
            }
            if !r.public && r.cache.as_ref().is_some_and(|cache| cache.enabled) {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!(
                        "routing host '{}' enables response cache on an authenticated route; cache is allowed only with public: true",
                        r.host
                    ),
                ));
            }
            if let Some(min_role) = r.min_role.as_deref() {
                let role = min_role.trim().to_ascii_uppercase();
                let valid =
                    ["OWNER", "ADMIN", "OPERATOR", "MEMBER", "VIEWER"].contains(&role.as_str());
                if !valid {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!(
                            "routing host '{}' has invalid min_role '{}'; expected OWNER, ADMIN, OPERATOR, MEMBER, or VIEWER",
                            r.host, min_role
                        ),
                    ));
                }
                if r.public {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!(
                            "routing host '{}' cannot combine public: true with min_role",
                            r.host
                        ),
                    ));
                }
                if !r.auth_bypass_paths.is_empty() {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!(
                            "routing host '{}' cannot combine min_role with auth_bypass_paths",
                            r.host
                        ),
                    ));
                }
            }
            for bypass in &r.auth_bypass_paths {
                if bypass.prefix.is_empty() || !bypass.prefix.starts_with('/') {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!(
                            "routing host '{}' has invalid auth_bypass_paths prefix '{}'; it must start with '/'",
                            r.host, bypass.prefix
                        ),
                    ));
                }
            }
        }
        let assertion_secret = self.auth.effective_gateway_assertion_secret();
        let assertion_key_id = self.auth.effective_gateway_assertion_key_id();
        if let Some(secret) = &assertion_secret {
            if secret.len() < crate::assertion::MIN_SECRET_LEN {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!(
                        "auth.gateway_assertion_secret / VOLTA_GATEWAY_ASSERTION_SECRET must be at least {} bytes",
                        crate::assertion::MIN_SECRET_LEN
                    ),
                ));
            }
            if let Err(error) = crate::assertion::validate_key_id(&assertion_key_id) {
                errors.push((
                    Self::EXIT_SCHEMA,
                    format!("invalid gateway assertion current key ID: {error}"),
                ));
            }
        } else if self.auth.gateway_assertion_key_id.is_some()
            || std::env::var("VOLTA_GATEWAY_ASSERTION_KEY_ID").is_ok()
        {
            errors.push((
                Self::EXIT_SCHEMA,
                "gateway assertion key ID requires a current assertion secret".into(),
            ));
        }
        let (previous_key_id, previous_secret) = self.auth.effective_gateway_assertion_previous();
        match (&previous_key_id, &previous_secret) {
            (Some(key_id), Some(secret)) => {
                if assertion_secret.is_none() {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        "previous gateway assertion key requires a current key".into(),
                    ));
                }
                if secret.len() < crate::assertion::MIN_SECRET_LEN {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!(
                            "previous gateway assertion secret must be at least {} bytes",
                            crate::assertion::MIN_SECRET_LEN
                        ),
                    ));
                }
                if let Err(error) = crate::assertion::validate_key_id(key_id) {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        format!("invalid gateway assertion previous key ID: {error}"),
                    ));
                }
                if key_id == &assertion_key_id {
                    errors.push((
                        Self::EXIT_SCHEMA,
                        "current and previous gateway assertion key IDs must differ".into(),
                    ));
                }
            }
            (None, None) => {}
            _ => errors.push((
                Self::EXIT_SCHEMA,
                "previous gateway assertion key ID and secret must be configured together".into(),
            )),
        }
        if self.plugins.iter().any(|plugin| plugin.name == "monetizer")
            && assertion_secret.is_none()
        {
            errors.push((
                Self::EXIT_SCHEMA,
                "monetizer plugin requires auth.gateway_assertion_secret or VOLTA_GATEWAY_ASSERTION_SECRET"
                    .into(),
            ));
        }
        // ── #95: SPEC §11.8 の 3 / 4 / 5 に相当する検査（今まで無かった） ──

        // 3: backend URL がパースできるか。文字列として置かれているだけなので、
        //    間違っていても起動は成功し、**全リクエストが 502 になって初めて分かる**。
        for r in &self.routing {
            for b in r.all_backends() {
                if b.parse::<hyper::Uri>().is_err() {
                    errors.push((
                        Self::EXIT_BACKEND_URL,
                        format!(
                            "routing host '{}': backend URL is unparsable: {}",
                            r.host, b
                        ),
                    ));
                    continue;
                }
                if !b.starts_with("http://") && !b.starts_with("https://") {
                    errors.push((
                        Self::EXIT_BACKEND_URL,
                        format!(
                            "routing host '{}': backend must start with http:// or https://: {}",
                            r.host, b
                        ),
                    ));
                }
            }
        }

        // 4: 未知の plugin 名。以前は起動時に warn を出して skip するだけで、
        //    typo に気付けなかった（設定したつもりの plugin が動いていない）。
        for pl in &self.plugins {
            if pl.plugin_type == "native"
                && !crate::plugin::PluginManager::BUILTIN_PLUGINS.contains(&pl.name.as_str())
            {
                errors.push((
                    Self::EXIT_UNKNOWN_PLUGIN,
                    format!(
                        "unknown plugin '{}' (built-in: {})",
                        pl.name,
                        crate::plugin::PluginManager::BUILTIN_PLUGINS.join(", ")
                    ),
                ));
            }
        }

        // 5: TLS challenge に必要な資格情報。dns-01 を指定したのに provider や
        //    token が無いと、証明書取得の段で初めて失敗する。
        if let Some(ref tls) = self.tls {
            if tls.challenge == "dns-01" {
                if tls.dns_provider.is_none() {
                    errors.push((
                        Self::EXIT_TLS_CREDENTIALS,
                        "tls.challenge is dns-01 but tls.dns_provider is not set".into(),
                    ));
                }
                if tls.dns_api_token.is_none() && std::env::var("CF_DNS_API_TOKEN").is_err() {
                    errors.push((Self::EXIT_TLS_CREDENTIALS,
                        "tls.challenge is dns-01 but neither tls.dns_api_token nor CF_DNS_API_TOKEN is set".into()));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Build routing table: host → RouteInfo
    /// GW-45: host keys are lowercased for consistent lookup
    pub fn routing_table(&self) -> HashMap<String, crate::proxy::RouteInfo> {
        self.routing
            .iter()
            .map(|r| {
                (
                    r.host.to_lowercase(),
                    crate::proxy::RouteInfo {
                        backends: r.all_backends(),
                        weights: r.all_weights(),
                        app_id: r.app_id.clone(),
                        min_role: r.min_role.clone(),
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
                    },
                )
            })
            .collect()
    }

    /// Build CORS origins table: host → allowed origins
    /// GW-44: empty cors_origins = no CORS headers (not wildcard)
    pub fn cors_table(&self) -> HashMap<String, Vec<String>> {
        self.routing
            .iter()
            .filter(|r| !r.cors_origins.is_empty())
            .map(|r| (r.host.to_lowercase(), r.cors_origins.clone()))
            .collect()
    }

    /// Build IP allowlist: host → Vec<IpNet>
    pub fn ip_allowlist_table(&self) -> HashMap<String, Vec<ipnet::IpNet>> {
        self.routing
            .iter()
            .filter(|r| !r.ip_allowlist.is_empty())
            .map(|r| {
                (
                    r.host.to_lowercase(),
                    r.ip_allowlist
                        .iter()
                        .filter_map(|c| c.parse().ok())
                        .collect(),
                )
            })
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
            min_role: None,
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
            min_role: None,
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
                WeightedBackend {
                    url: "http://a:3000".into(),
                    weight: 90,
                },
                WeightedBackend {
                    url: "http://b:3000".into(),
                    weight: 10,
                },
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
            backends: vec![WeightedBackend {
                url: "http://a:3000".into(),
                weight: 90,
            }],
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
            min_role: None,
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
            min_role: None,
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
                WeightedBackend {
                    url: "http://a:3000".into(),
                    weight: 70,
                },
                WeightedBackend {
                    url: "http://b:3000".into(),
                    weight: 30,
                },
            ],
        );
        assert_eq!(route.all_weights(), vec![70u32, 30u32]);
    }

    // ── GatewayConfig::validate ──────────────────────────────────

    #[test]
    fn reuse_port_defaults_to_false() {
        // #74: 既定で有効になると、既存デプロイで**古いプロセスが残っていることに
        // 気付かないまま新旧が同時に動く**。opt-in であることを固定する。
        let cfg = parse_config(&minimal_config_yaml(""));
        assert!(!cfg.server.reuse_port);
    }

    #[test]
    fn reuse_port_can_be_enabled() {
        let yaml = r#"
server:
  port: 8080
  reuse_port: true
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: example.com
    backend: "http://backend:3000"
"#;
        assert!(parse_config(yaml).server.reuse_port);
    }

    #[test]
    fn validate_passes_for_minimal_valid_config() {
        let cfg = parse_config(&minimal_config_yaml(""));
        assert!(cfg.validate().is_ok());
    }

    // ── #95: --validate の終了コード分類 ─────────────────────────
    //
    // CI が「何が悪かったのか」を終了コードで区別できることを固定する。

    #[test]
    fn validate_detailed_reports_backend_url_code() {
        // scheme が無い backend は起動時には気付けず、接続で初めて落ちる
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: example.com
    backend: "backend:3000"
"#;
        let errs = parse_config(yaml)
            .validate_detailed()
            .expect_err("should fail");
        assert!(
            errs.iter()
                .any(|(c, _)| *c == GatewayConfig::EXIT_BACKEND_URL),
            "expected EXIT_BACKEND_URL, got {:?}",
            errs
        );
    }

    #[test]
    fn validate_detailed_reports_unknown_plugin_code() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: example.com
    backend: "http://backend:3000"
plugins:
  - name: no-such-plugin
"#;
        let errs = parse_config(yaml)
            .validate_detailed()
            .expect_err("should fail");
        assert!(
            errs.iter()
                .any(|(c, _)| *c == GatewayConfig::EXIT_UNKNOWN_PLUGIN),
            "expected EXIT_UNKNOWN_PLUGIN, got {:?}",
            errs
        );
    }

    #[test]
    fn validate_detailed_accepts_builtin_plugin() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: example.com
    backend: "http://backend:3000"
plugins:
  - name: api-key-auth
"#;
        let cfg = parse_config(yaml);
        assert!(
            cfg.validate_detailed().is_ok(),
            "{:?}",
            cfg.validate_detailed()
        );
    }

    #[test]
    fn validate_detailed_reports_tls_credentials_code() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: example.com
    backend: "http://backend:3000"
tls:
  enabled: true
  port: 8443
  domains: ["example.com"]
  contact_email: "admin@example.com"
  challenge: dns-01
"#;
        // CF_DNS_API_TOKEN が環境にあると通ってしまうので、その場合はスキップ
        if std::env::var("CF_DNS_API_TOKEN").is_ok() {
            return;
        }
        let errs = parse_config(yaml)
            .validate_detailed()
            .expect_err("should fail");
        assert!(
            errs.iter()
                .any(|(c, _)| *c == GatewayConfig::EXIT_TLS_CREDENTIALS),
            "expected EXIT_TLS_CREDENTIALS, got {:?}",
            errs
        );
    }

    #[test]
    fn validate_string_api_still_works() {
        // 既存の呼び出し元（Vec<String> を期待する側）が壊れていないこと
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: example.com
    backend: "backend:3000"
"#;
        let errs = parse_config(yaml).validate().expect_err("should fail");
        assert!(errs.iter().any(|m| m.contains("http://")), "{:?}", errs);
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
    fn validate_accepts_gateway_assertion_dual_key_rotation() {
        let yaml = r#"
server:
  port: 8080
auth:
  volta_url: "http://localhost:7070"
  gateway_assertion_key_id: "2026-09"
  gateway_assertion_secret: "current-current-current-current-1234"
  gateway_assertion_previous_key_id: "2026-08"
  gateway_assertion_previous_secret: "previous-previous-previous-prev-1234"
routing:
  - host: "example.com"
    backend: "http://a:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_incomplete_or_ambiguous_assertion_rotation() {
        let incomplete = r#"
server: { port: 8080 }
auth:
  volta_url: "http://localhost:7070"
  gateway_assertion_key_id: "2026-09"
  gateway_assertion_secret: "current-current-current-current-1234"
  gateway_assertion_previous_key_id: "2026-08"
routing:
  - host: "example.com"
    backend: "http://a:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(incomplete).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("configured together")));

        let duplicate_id = incomplete.replace(
            "gateway_assertion_previous_key_id: \"2026-08\"",
            "gateway_assertion_previous_key_id: \"2026-09\"\n  gateway_assertion_previous_secret: \"previous-previous-previous-prev-1234\"",
        );
        let cfg: GatewayConfig = serde_yaml::from_str(&duplicate_id).unwrap();
        assert!(cfg
            .validate()
            .unwrap_err()
            .iter()
            .any(|error| error.contains("must differ")));
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
        assert!(errs
            .iter()
            .any(|e| e.contains("protocol must be 'tcp' or 'udp'")));
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
        // GW-15: graceful drain timeout default is 30s.
        assert_eq!(cfg.server.drain_timeout_secs, 30);
    }

    #[test]
    fn drain_timeout_secs_is_configurable() {
        let yaml = r#"
server:
  port: 8080
  drain_timeout_secs: 5
auth:
  volta_url: "http://localhost:7070"
routing:
  - host: "example.com"
    backend: "http://a:3000"
"#;
        let cfg: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.server.drain_timeout_secs, 5);
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

fn default_port() -> u16 {
    8080
}
fn default_read_timeout() -> u64 {
    10
}
fn default_request_timeout() -> u64 {
    30
}
fn default_drain_timeout() -> u64 {
    30
}
fn default_volta_url() -> String {
    "http://localhost:7070".into()
}
fn default_verify_path() -> String {
    "/auth/verify".into()
}
fn default_auth_timeout() -> u64 {
    500
}
fn default_pool_max_idle() -> usize {
    32
}
fn default_cookie_name() -> Option<String> {
    Some("__volta_session".into())
}
fn default_rps() -> u32 {
    1000
}
fn default_per_ip_rps() -> u32 {
    100
}
fn default_pool_idle() -> usize {
    64
}
fn default_idle_timeout() -> u64 {
    90
}
fn default_hc_interval() -> u64 {
    30
}
fn default_hc_path() -> String {
    "/healthz".into()
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}
fn default_tls_port() -> u16 {
    443
}
fn default_acme_cache() -> String {
    "./acme-cache".into()
}
fn default_l4_proto() -> String {
    "tcp".into()
}
fn default_sample_rate() -> f64 {
    1.0
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: default_rps(),
            per_ip_rps: default_per_ip_rps(),
        }
    }
}
impl Default for BackendPoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: default_pool_idle(),
            idle_timeout_secs: default_idle_timeout(),
        }
    }
}
impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_hc_interval(),
            path: default_hc_path(),
        }
    }
}
impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}
