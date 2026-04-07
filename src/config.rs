use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_read_timeout")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteEntry {
    pub host: String,
    /// Single backend (simple)
    #[serde(default)]
    pub backend: Option<String>,
    /// Multiple backends for load balancing (round-robin)
    #[serde(default)]
    pub backends: Vec<String>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub ip_allowlist: Vec<String>,
}

impl RouteEntry {
    /// Get all backend URLs (merges `backend` and `backends`).
    pub fn all_backends(&self) -> Vec<String> {
        let mut result: Vec<String> = self.backends.clone();
        if let Some(ref b) = self.backend {
            if !result.contains(b) { result.insert(0, b.clone()); }
        }
        result
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendPoolConfig {
    #[serde(default = "default_pool_idle")]
    pub max_idle_per_host: usize,
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_hc_path")]
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
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
                errors.push(format!("duplicate routing host: {}", r.host));
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
        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Build routing table: host → (backend_urls, app_id)
    pub fn routing_table(&self) -> HashMap<String, (Vec<String>, Option<String>)> {
        self.routing
            .iter()
            .map(|r| (r.host.clone(), (r.all_backends(), r.app_id.clone())))
            .collect()
    }

    /// Build IP allowlist: host → Vec<IpNet>
    pub fn ip_allowlist_table(&self) -> HashMap<String, Vec<ipnet::IpNet>> {
        self.routing.iter()
            .filter(|r| !r.ip_allowlist.is_empty())
            .map(|r| (
                r.host.clone(),
                r.ip_allowlist.iter().filter_map(|c| c.parse().ok()).collect(),
            ))
            .collect()
    }
}

fn default_port() -> u16 { 8080 }
fn default_read_timeout() -> u64 { 10 }
fn default_request_timeout() -> u64 { 30 }
fn default_volta_url() -> String { "http://localhost:7070".into() }
fn default_verify_path() -> String { "/auth/verify".into() }
fn default_auth_timeout() -> u64 { 500 }
fn default_pool_max_idle() -> usize { 32 }
fn default_rps() -> u32 { 1000 }
fn default_per_ip_rps() -> u32 { 100 }
fn default_pool_idle() -> usize { 64 }
fn default_idle_timeout() -> u64 { 90 }
fn default_hc_interval() -> u64 { 30 }
fn default_hc_path() -> String { "/healthz".into() }
fn default_log_level() -> String { "info".into() }
fn default_log_format() -> String { "json".into() }

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
