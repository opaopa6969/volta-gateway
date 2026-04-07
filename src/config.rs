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
    pub backend: String,
    #[serde(default)]
    pub app_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rps")]
    pub requests_per_second: u32,
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

    /// Build routing table: host → (backend_url, app_id)
    pub fn routing_table(&self) -> HashMap<String, (String, Option<String>)> {
        self.routing
            .iter()
            .map(|r| (r.host.clone(), (r.backend.clone(), r.app_id.clone())))
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
fn default_rps() -> u32 { 100 }
fn default_hc_interval() -> u64 { 30 }
fn default_hc_path() -> String { "/healthz".into() }
fn default_log_level() -> String { "info".into() }
fn default_log_format() -> String { "json".into() }

impl Default for RateLimitConfig {
    fn default() -> Self { Self { requests_per_second: default_rps() } }
}
impl Default for HealthCheckConfig {
    fn default() -> Self { Self { interval_secs: default_hc_interval(), path: default_hc_path() } }
}
impl Default for LoggingConfig {
    fn default() -> Self { Self { level: default_log_level(), format: default_log_format() } }
}
