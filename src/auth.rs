use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::Empty;
use bytes::Bytes;
use std::collections::HashMap;
use std::time::Duration;

use crate::config::AuthConfig;

/// Result of volta /auth/verify call.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// 200 — authenticated. Contains X-Volta-* headers.
    Authenticated(HashMap<String, String>),
    /// 401/302 — redirect to login.
    Redirect(String),
    /// 403 — access denied.
    Denied,
    /// 5xx or timeout — volta is down.
    Error(String),
}

/// HTTP client for volta /auth/verify. Connection-pooled, fail-closed.
#[derive(Clone)]
pub struct VoltaAuthClient {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    base_url: String,
    verify_path: String,
    timeout: Duration,
}

impl VoltaAuthClient {
    pub fn new(config: &AuthConfig) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(config.pool_max_idle)
            .build_http();

        Self {
            client,
            base_url: config.volta_url.clone(),
            verify_path: config.verify_path.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
        }
    }

    /// Call volta /auth/verify with forwarded headers and cookies.
    pub async fn check(
        &self,
        host: &str,
        uri: &str,
        proto: &str,
        cookie: Option<&str>,
        app_id: Option<&str>,
    ) -> AuthResult {
        let url = format!("{}{}", self.base_url, self.verify_path);

        let mut builder = Request::builder()
            .method("GET")
            .uri(url.parse::<Uri>().unwrap_or_default())
            .header("X-Forwarded-Host", host)
            .header("X-Forwarded-Uri", uri)
            .header("X-Forwarded-Proto", proto);

        if let Some(c) = cookie {
            builder = builder.header("Cookie", c);
        }
        if let Some(id) = app_id {
            builder = builder.header("X-Volta-App-Id", id);
        }

        let req = match builder.body(Empty::<Bytes>::new()) {
            Ok(r) => r,
            Err(e) => return AuthResult::Error(format!("build request: {e}")),
        };

        let result = tokio::time::timeout(self.timeout, self.client.request(req)).await;

        match result {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                match status {
                    200 => {
                        let mut volta_headers = HashMap::new();
                        for (name, value) in resp.headers() {
                            let key = name.as_str();
                            if key.starts_with("x-volta-") {
                                if let Ok(v) = value.to_str() {
                                    volta_headers.insert(key.to_string(), v.to_string());
                                }
                            }
                        }
                        AuthResult::Authenticated(volta_headers)
                    }
                    401 => {
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("/login")
                            .to_string();
                        AuthResult::Redirect(location)
                    }
                    302 => {
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("/login")
                            .to_string();
                        AuthResult::Redirect(location)
                    }
                    403 => AuthResult::Denied,
                    _ => AuthResult::Error(format!("volta returned {status}")),
                }
            }
            Ok(Err(e)) => AuthResult::Error(format!("volta request failed: {e}")),
            Err(_) => AuthResult::Error("volta auth timeout".into()),
        }
    }

    /// Health check — is volta alive?
    pub async fn health(&self) -> bool {
        let url = format!("{}/healthz", self.base_url);
        let req = Request::builder()
            .uri(url.parse::<Uri>().unwrap_or_default())
            .body(Empty::<Bytes>::new());

        match req {
            Ok(r) => {
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.client.request(r),
                ).await;
                matches!(result, Ok(Ok(resp)) if resp.status().is_success())
            }
            Err(_) => false,
        }
    }
}
