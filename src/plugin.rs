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
