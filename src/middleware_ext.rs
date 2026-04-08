//! #14: Middleware Extension architecture — async-capable, route-aware.
//!
//! Extends the plugin system with:
//! - Async execution (can make HTTP calls, DB lookups)
//! - Access to RouteEntry config
//! - Access to AuthResult (post-auth middleware)
//! - Init/validate lifecycle with serde_json config

use bytes::Bytes;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// Middleware extension context — richer than PluginContext.
pub struct ExtensionContext {
    pub method: String,
    pub host: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    /// Set to short-circuit with error response
    pub reject: Option<(u16, String)>,
    /// Headers to add to request/response
    pub add_headers: HashMap<String, String>,
    /// Headers to remove
    pub remove_headers: Vec<String>,
    /// Arbitrary data for passing between extensions
    pub metadata: HashMap<String, String>,
}

/// Extension error with status code.
#[derive(Debug)]
pub struct ExtensionError {
    pub status: u16,
    pub message: String,
}

impl ExtensionError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }
}

/// Middleware Extension trait — async-capable.
#[async_trait::async_trait]
pub trait MiddlewareExtension: Send + Sync {
    fn name(&self) -> &str;

    /// Validate config at startup. Return Err to prevent loading.
    fn validate_config(config: &Value) -> Result<(), String> where Self: Sized { Ok(()) }

    /// Called after auth, before backend forward.
    async fn on_request(&self, ctx: &mut ExtensionContext) -> Result<(), ExtensionError> { Ok(()) }

    /// Called after backend response, before returning to client.
    async fn on_response(&self, ctx: &mut ExtensionContext) -> Result<(), ExtensionError> { Ok(()) }
}

/// Built-in extensions.
pub mod builtin {
    use super::*;

    /// JWT validation extension — verify JWT in Authorization header.
    /// Useful for API-only routes where volta-auth-proxy is not used.
    pub struct JwtValidator {
        pub secret: String,
        pub issuer: Option<String>,
    }

    #[async_trait::async_trait]
    impl MiddlewareExtension for JwtValidator {
        fn name(&self) -> &str { "jwt-validator" }

        async fn on_request(&self, ctx: &mut ExtensionContext) -> Result<(), ExtensionError> {
            let auth_header = ctx.headers.get("authorization")
                .ok_or_else(|| ExtensionError::new(401, "Authorization header required"))?;

            if !auth_header.starts_with("Bearer ") {
                return Err(ExtensionError::new(401, "Bearer token required"));
            }

            let _token = &auth_header[7..];
            // TODO: actual JWT verification with the secret
            // For now, just check the token is present and non-empty
            if _token.is_empty() {
                return Err(ExtensionError::new(401, "Empty token"));
            }

            // In a real implementation: decode JWT, verify signature, check expiry/issuer
            // ctx.metadata.insert("jwt.sub", claims.sub);
            // ctx.user_id = Some(claims.sub);

            Ok(())
        }
    }

    /// Request ID propagation extension — ensures every request has a unique ID.
    pub struct RequestIdPropagation;

    #[async_trait::async_trait]
    impl MiddlewareExtension for RequestIdPropagation {
        fn name(&self) -> &str { "request-id-propagation" }

        async fn on_request(&self, ctx: &mut ExtensionContext) -> Result<(), ExtensionError> {
            if !ctx.headers.contains_key("x-request-id") {
                ctx.add_headers.insert(
                    "x-request-id".into(),
                    uuid::Uuid::new_v4().to_string(),
                );
            }
            Ok(())
        }
    }
}

/// Extension manager.
pub struct ExtensionManager {
    extensions: Vec<(String, Arc<dyn MiddlewareExtension>)>,
}

impl ExtensionManager {
    pub fn new() -> Self {
        Self { extensions: Vec::new() }
    }

    pub fn register(&mut self, name: String, ext: Arc<dyn MiddlewareExtension>) {
        info!(extension = %name, "middleware extension registered");
        self.extensions.push((name, ext));
    }

    pub async fn run_request(&self, ctx: &mut ExtensionContext) -> Option<(u16, String)> {
        for (name, ext) in &self.extensions {
            match ext.on_request(ctx).await {
                Ok(()) => {
                    if let Some(reject) = ctx.reject.take() {
                        return Some(reject);
                    }
                }
                Err(e) => {
                    warn!(extension = %name, status = e.status, error = %e.message);
                    return Some((e.status, e.message));
                }
            }
        }
        None
    }

    pub async fn run_response(&self, ctx: &mut ExtensionContext) {
        for (name, ext) in &self.extensions {
            if let Err(e) = ext.on_response(ctx).await {
                warn!(extension = %name, error = %e.message, "response extension error");
            }
        }
    }
}
