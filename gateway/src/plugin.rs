//! #11: Plugin system with tramli-managed lifecycle.
//!
//! Plugin lifecycle (tramli SM pattern):
//!   LOADED → VALIDATED → ACTIVE ←→ ERROR
//!              ↓
//!           REJECTED (validation failed)
//!
//! Phase 1: Trait-based plugin interface (native Rust plugins).
//! Phase 2: Wasm runtime (wasmtime) for sandboxed plugins.

use bytes::Bytes;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Plugin configuration from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    /// Plugin type: "native" (built-in) or "wasm" (future)
    #[serde(default = "default_plugin_type")]
    pub plugin_type: String,
    /// Path to plugin (Wasm file for wasm type)
    #[serde(default)]
    pub path: Option<String>,
    /// Plugin-specific config
    #[serde(default)]
    pub config: HashMap<String, String>,
    /// When to run: "request" or "response"
    #[serde(default = "default_phase")]
    pub phase: String,
}

fn default_plugin_type() -> String { "native".into() }
fn default_phase() -> String { "request".into() }

/// Plugin lifecycle state (tramli SM pattern).
#[derive(Debug, Clone, PartialEq)]
pub enum PluginState {
    Loaded,
    Validated,
    Active,
    Error(String),
    Rejected(String),
}

/// Context passed to plugins for request/response modification.
pub struct PluginContext {
    pub method: String,
    pub host: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
    /// Plugin can set this to short-circuit with an error response
    pub reject: Option<(u16, String)>,
    /// Plugin can add headers to the request/response
    pub add_headers: HashMap<String, String>,
    /// Plugin can remove headers
    pub remove_headers: Vec<String>,
}

/// Plugin trait — implement this for native plugins.
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn on_request(&self, ctx: &mut PluginContext) -> Result<(), String>;
    fn on_response(&self, ctx: &mut PluginContext) -> Result<(), String>;
}

/// Built-in plugins.
///
/// Available plugins:
/// - `api-key-auth`: API key authentication (request phase)
/// - `header-injector`: Add/set headers on request/response
/// - `rate-limit-by-user`: Per-user rate limiting based on X-Volta-User-Id (request phase)
pub mod builtin {
    use super::*;

    /// API Key authentication plugin.
    pub struct ApiKeyAuth {
        pub header: String,
        pub valid_keys: Vec<String>,
    }

    impl Plugin for ApiKeyAuth {
        fn name(&self) -> &str { "api-key-auth" }

        fn on_request(&self, ctx: &mut PluginContext) -> Result<(), String> {
            match ctx.headers.get(&self.header) {
                Some(key) if self.valid_keys.contains(key) => Ok(()),
                Some(_) => {
                    ctx.reject = Some((403, "Invalid API key".into()));
                    Ok(())
                }
                None => {
                    ctx.reject = Some((401, "API key required".into()));
                    Ok(())
                }
            }
        }

        fn on_response(&self, _ctx: &mut PluginContext) -> Result<(), String> { Ok(()) }
    }

    /// Per-user rate limiting plugin.
    /// Uses X-Volta-User-Id from auth response to enforce per-user request limits.
    /// Useful for SaaS: prevent a single user/tenant from monopolizing resources.
    pub struct RateLimitByUser {
        pub max_requests: u64,
        pub window_secs: u64,
        pub user_header: String,
        state: Arc<std::sync::Mutex<HashMap<String, (u64, std::time::Instant)>>>,
    }

    impl RateLimitByUser {
        pub fn new(max_requests: u64, window_secs: u64, user_header: String) -> Self {
            Self {
                max_requests, window_secs, user_header,
                state: Arc::new(std::sync::Mutex::new(HashMap::new())),
            }
        }
    }

    impl Plugin for RateLimitByUser {
        fn name(&self) -> &str { "rate-limit-by-user" }

        fn on_request(&self, ctx: &mut PluginContext) -> Result<(), String> {
            let user_id = match ctx.headers.get(&self.user_header) {
                Some(id) => id.clone(),
                None => return Ok(()), // No user ID = skip (unauthenticated or public route)
            };

            let mut state = self.state.lock().unwrap();
            let entry = state.entry(user_id).or_insert((0, std::time::Instant::now()));

            if entry.1.elapsed() >= std::time::Duration::from_secs(self.window_secs) {
                *entry = (1, std::time::Instant::now());
            } else {
                entry.0 += 1;
                if entry.0 > self.max_requests {
                    ctx.reject = Some((429, format!(
                        "User rate limit exceeded ({}/{}s)", self.max_requests, self.window_secs
                    )));
                    ctx.add_headers.insert("Retry-After".into(), self.window_secs.to_string());
                }
            }
            Ok(())
        }

        fn on_response(&self, _ctx: &mut PluginContext) -> Result<(), String> { Ok(()) }
    }

    /// Monetizer plugin — enriches requests with billing headers (X-Monetizer-*).
    /// Calls monetizer service /verify endpoint, caches responses in-memory.
    ///
    /// Config:
    ///   verify_url: "http://monetizer:3001/__monetizer/verify"
    ///   config_id: monetizer config UUID for this tenant
    ///   cache_ttl_secs: "5" (default)
    ///   user_header: "x-volta-user-id" (default)
    pub struct Monetizer {
        pub verify_url: String,
        pub config_id: String,
        pub cache_ttl_secs: u64,
        pub user_header: String,
        cache: Arc<Mutex<HashMap<String, (MonetizerBilling, std::time::Instant)>>>,
        http: reqwest::Client,
    }

    #[derive(Debug, Clone, serde::Deserialize)]
    struct MonetizerBilling {
        plan: String,
        status: String,
        features: String,
        #[serde(rename = "showAds")]
        show_ads: String,
        #[serde(rename = "trialEnd")]
        trial_end: String,
    }

    impl Monetizer {
        pub fn new(verify_url: String, config_id: String, cache_ttl_secs: u64, user_header: String) -> Self {
            Self {
                verify_url,
                config_id,
                cache_ttl_secs,
                user_header,
                cache: Arc::new(Mutex::new(HashMap::new())),
                http: reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(2))
                    .build()
                    .unwrap(),
            }
        }

        const MAX_CACHE_ENTRIES: usize = 10_000;

        fn get_cached(&self, user_id: &str) -> Option<MonetizerBilling> {
            let mut cache = self.cache.lock().unwrap();
            if let Some((billing, ts)) = cache.get(user_id) {
                if ts.elapsed() < std::time::Duration::from_secs(self.cache_ttl_secs) {
                    return Some(billing.clone());
                }
                // 期限切れエントリを即削除
                let key = user_id.to_string();
                drop(cache);
                self.cache.lock().unwrap().remove(&key);
                return None;
            }
            None
        }

        fn set_cached(&self, user_id: &str, billing: MonetizerBilling) {
            let mut cache = self.cache.lock().unwrap();
            // 安全弁: 上限超過で全クリア (TTL 5秒で自然に再構築)
            if cache.len() >= Self::MAX_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(user_id.to_string(), (billing, std::time::Instant::now()));
        }

        fn fetch_billing(&self, user_id: &str) -> Result<MonetizerBilling, String> {
            let url = format!("{}?user={}&config={}", self.verify_url, user_id, self.config_id);
            let handle = tokio::runtime::Handle::current();
            let http = self.http.clone();
            tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let resp = http.get(&url).send().await
                        .map_err(|e| format!("monetizer verify request failed: {}", e))?;
                    if !resp.status().is_success() {
                        return Err(format!("monetizer verify returned {}", resp.status()));
                    }
                    resp.json::<MonetizerBilling>().await
                        .map_err(|e| format!("monetizer verify parse failed: {}", e))
                })
            })
        }
    }

    impl Plugin for Monetizer {
        fn name(&self) -> &str { "monetizer" }

        fn on_request(&self, ctx: &mut PluginContext) -> Result<(), String> {
            let user_id = match ctx.headers.get(&self.user_header) {
                Some(id) => id.clone(),
                None => {
                    // 認証なしユーザー → free プランのデフォルトヘッダー
                    ctx.add_headers.insert("X-Monetizer-Plan".into(), "free".into());
                    ctx.add_headers.insert("X-Monetizer-Status".into(), "none".into());
                    ctx.add_headers.insert("X-Monetizer-Features".into(), "".into());
                    ctx.add_headers.insert("X-Monetizer-Show-Ads".into(), "true".into());
                    return Ok(());
                }
            };

            let billing = match self.get_cached(&user_id) {
                Some(b) => b,
                None => {
                    let b = self.fetch_billing(&user_id)?;
                    self.set_cached(&user_id, b.clone());
                    b
                }
            };

            ctx.add_headers.insert("X-Monetizer-Plan".into(), billing.plan);
            ctx.add_headers.insert("X-Monetizer-Status".into(), billing.status);
            ctx.add_headers.insert("X-Monetizer-Features".into(), billing.features);
            ctx.add_headers.insert("X-Monetizer-Show-Ads".into(), billing.show_ads);
            if !billing.trial_end.is_empty() {
                ctx.add_headers.insert("X-Monetizer-Trial-End".into(), billing.trial_end);
            }

            Ok(())
        }

        fn on_response(&self, _ctx: &mut PluginContext) -> Result<(), String> { Ok(()) }
    }

    /// Request/response header injection plugin.
    pub struct HeaderInjector {
        pub request_headers: HashMap<String, String>,
        pub response_headers: HashMap<String, String>,
    }

    impl Plugin for HeaderInjector {
        fn name(&self) -> &str { "header-injector" }

        fn on_request(&self, ctx: &mut PluginContext) -> Result<(), String> {
            for (k, v) in &self.request_headers {
                ctx.add_headers.insert(k.clone(), v.clone());
            }
            Ok(())
        }

        fn on_response(&self, ctx: &mut PluginContext) -> Result<(), String> {
            for (k, v) in &self.response_headers {
                ctx.add_headers.insert(k.clone(), v.clone());
            }
            Ok(())
        }
    }
}

/// Plugin manager — loads, validates, and runs plugins.
pub struct PluginManager {
    plugins: Vec<(PluginConfig, PluginState, Arc<dyn Plugin>)>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    /// Register a native plugin. Transitions: LOADED → VALIDATED → ACTIVE.
    pub fn register(&mut self, config: PluginConfig, plugin: Arc<dyn Plugin>) {
        info!(plugin = plugin.name(), "plugin loaded");
        let state = PluginState::Validated; // Native plugins are always valid
        info!(plugin = plugin.name(), "plugin validated → active");
        self.plugins.push((config, PluginState::Active, plugin));
    }

    /// Load built-in plugins from config.
    pub fn load_from_config(configs: &[PluginConfig]) -> Self {
        let mut mgr = Self::new();
        for config in configs {
            match config.name.as_str() {
                "api-key-auth" => {
                    let header = config.config.get("header").cloned()
                        .unwrap_or_else(|| "x-api-key".into());
                    let keys: Vec<String> = config.config.get("keys")
                        .map(|s| s.split(',').map(|k| k.trim().to_string()).collect())
                        .unwrap_or_default();
                    mgr.register(config.clone(), Arc::new(builtin::ApiKeyAuth {
                        header,
                        valid_keys: keys,
                    }));
                }
                "rate-limit-by-user" => {
                    let max_req: u64 = config.config.get("max_requests")
                        .and_then(|s| s.parse().ok()).unwrap_or(100);
                    let window: u64 = config.config.get("window_secs")
                        .and_then(|s| s.parse().ok()).unwrap_or(60);
                    let header = config.config.get("user_header")
                        .cloned().unwrap_or_else(|| "x-volta-user-id".into());
                    mgr.register(config.clone(), Arc::new(builtin::RateLimitByUser::new(
                        max_req, window, header,
                    )));
                }
                "monetizer" => {
                    let verify_url = config.config.get("verify_url").cloned()
                        .unwrap_or_else(|| "http://monetizer:3001/__monetizer/verify".into());
                    let config_id = config.config.get("config_id").cloned()
                        .unwrap_or_default();
                    let cache_ttl: u64 = config.config.get("cache_ttl_secs")
                        .and_then(|s| s.parse().ok()).unwrap_or(5);
                    let user_header = config.config.get("user_header")
                        .cloned().unwrap_or_else(|| "x-volta-user-id".into());
                    mgr.register(config.clone(), Arc::new(builtin::Monetizer::new(
                        verify_url, config_id, cache_ttl, user_header,
                    )));
                }
                "header-injector" => {
                    let mut req_headers = HashMap::new();
                    let mut resp_headers = HashMap::new();
                    for (k, v) in &config.config {
                        if k.starts_with("req.") {
                            req_headers.insert(k[4..].to_string(), v.clone());
                        } else if k.starts_with("resp.") {
                            resp_headers.insert(k[5..].to_string(), v.clone());
                        }
                    }
                    mgr.register(config.clone(), Arc::new(builtin::HeaderInjector {
                        request_headers: req_headers,
                        response_headers: resp_headers,
                    }));
                }
                other => {
                    warn!(plugin = other, "unknown plugin, skipping");
                }
            }
        }
        mgr
    }

    /// Run request-phase plugins. Returns Some((status, body)) to short-circuit.
    pub fn run_request(&self, ctx: &mut PluginContext) -> Option<(u16, String)> {
        for (config, state, plugin) in &self.plugins {
            if *state != PluginState::Active { continue; }
            if config.phase != "request" && config.phase != "both" { continue; }
            if let Err(e) = plugin.on_request(ctx) {
                warn!(plugin = plugin.name(), error = %e, "plugin request error");
                continue;
            }
            if let Some(reject) = ctx.reject.take() {
                return Some(reject);
            }
        }
        None
    }

    /// Run response-phase plugins.
    pub fn run_response(&self, ctx: &mut PluginContext) {
        for (config, state, plugin) in &self.plugins {
            if *state != PluginState::Active { continue; }
            if config.phase != "response" && config.phase != "both" { continue; }
            if let Err(e) = plugin.on_response(ctx) {
                warn!(plugin = plugin.name(), error = %e, "plugin response error");
            }
        }
    }

    /// Get plugin states for admin API.
    pub fn states(&self) -> Vec<(String, String)> {
        self.plugins.iter()
            .map(|(c, s, _)| (c.name.clone(), format!("{:?}", s)))
            .collect()
    }
}
