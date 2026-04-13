use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::Empty;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
/// #33: Auth result cache entry.
#[derive(Clone)]
struct AuthCacheEntry {
    result: AuthResult,
    created: Instant,
}

#[derive(Clone)]
pub struct VoltaAuthClient {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    base_url: String,
    verify_path: String,
    timeout: Duration,
    /// #33: Short-lived auth cache (cookie hash → result). TTL = 5s.
    auth_cache: Arc<Mutex<HashMap<u64, AuthCacheEntry>>>,
    cache_ttl: Duration,
    /// DD-005 Phase 0: In-process JWT session verifier (optional).
    session_verifier: Option<volta_auth_core::session::SessionVerifier>,
    /// #51: Public-facing auth URL for redirect allowlist (e.g. https://auth.example.com).
    auth_public_url: Option<String>,
}

impl VoltaAuthClient {
    pub fn new(config: &AuthConfig) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(config.pool_max_idle)
            .build_http();

        // DD-005 Phase 0: Build in-process JWT verifier if secret is configured
        let session_verifier = config.jwt_secret.as_ref().map(|secret| {
            let jwt = volta_auth_core::jwt::JwtVerifier::new_hs256(secret.as_bytes());
            let cookie_name = config.cookie_name.as_deref().unwrap_or("__volta_session");
            tracing::info!("in-process JWT verify enabled (cookie: {})", cookie_name);
            volta_auth_core::session::SessionVerifier::new(jwt, cookie_name)
        });

        Self {
            client,
            base_url: config.volta_url.clone(),
            verify_path: config.verify_path.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            auth_cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: Duration::from_secs(5),
            session_verifier,
            auth_public_url: config.auth_public_url.clone(),
        }
    }

    /// Call volta /auth/verify with forwarded headers and cookies.
    /// #33: Results are cached for 5s by cookie hash to skip redundant calls.
    /// `client_ip` is the resolved real client IP, forwarded as X-Real-IP so
    /// the auth proxy can apply IP-based rules (e.g. local network bypass).
    pub async fn check(
        &self,
        host: &str,
        uri: &str,
        proto: &str,
        cookie: Option<&str>,
        app_id: Option<&str>,
        client_ip: Option<&str>,
    ) -> AuthResult {
        // DD-005 Phase 0: In-process JWT verify (skip HTTP roundtrip)
        if let Some(ref verifier) = self.session_verifier {
            use volta_auth_core::session::SessionResult;
            match verifier.verify_cookie(cookie) {
                SessionResult::Valid(headers) => {
                    tracing::trace!(host = %host, "auth: in-process JWT verify OK");
                    return AuthResult::Authenticated(headers);
                }
                SessionResult::Expired => {
                    return AuthResult::Redirect("/login".into());
                }
                SessionResult::Invalid(e) => {
                    tracing::debug!(host = %host, error = %e, "auth: JWT invalid, falling back to HTTP");
                    // Fall through to HTTP verify — token may be in a format auth-core doesn't handle
                }
                SessionResult::NoSession => {
                    // No session cookie — fall through to HTTP verify (may redirect to login)
                }
            }
        }

        // #33: Auth cache lookup
        let cache_key = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            cookie.unwrap_or("").hash(&mut h);
            host.hash(&mut h);
            app_id.unwrap_or("").hash(&mut h);
            h.finish()
        };
        {
            let cache = self.auth_cache.lock().unwrap();
            if let Some(entry) = cache.get(&cache_key) {
                if entry.created.elapsed() < self.cache_ttl {
                    return entry.result.clone();
                }
            }
        }

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
        if let Some(ip) = client_ip {
            builder = builder.header("X-Real-IP", ip);
        }

        let req = match builder.body(Empty::<Bytes>::new()) {
            Ok(r) => r,
            Err(e) => return AuthResult::Error(format!("build request: {e}")),
        };

        let result = tokio::time::timeout(self.timeout, self.client.request(req)).await;

        let auth_result = match result {
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
                        // #51: Validate redirect destination (open redirect prevention)
                        AuthResult::Redirect(sanitize_redirect(&location, self.auth_public_url.as_deref()))
                    }
                    302 => {
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("/login")
                            .to_string();
                        AuthResult::Redirect(sanitize_redirect(&location, self.auth_public_url.as_deref()))
                    }
                    403 => AuthResult::Denied,
                    _ => AuthResult::Error(format!("volta returned {status}")),
                }
            }
            Ok(Err(e)) => AuthResult::Error(format!("volta request failed: {e}")),
            Err(_) => AuthResult::Error("volta auth timeout".into()),
        };

        // #33: Cache successful auth results (5s TTL)
        if matches!(auth_result, AuthResult::Authenticated(_)) {
            let mut cache = self.auth_cache.lock().unwrap();
            cache.insert(cache_key, AuthCacheEntry {
                result: auth_result.clone(),
                created: Instant::now(),
            });
            // GC: remove expired entries (simple cap)
            if cache.len() > 10_000 {
                cache.retain(|_, e| e.created.elapsed() < self.cache_ttl);
            }
        }

        auth_result
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

/// #51: Sanitize redirect URL — only allow relative paths or auth-proxy origin.
/// Prevents open redirect attacks via compromised auth-proxy responses.
fn sanitize_redirect(url: &str, auth_public_url: Option<&str>) -> String {
    // Relative paths are always safe
    if url.starts_with('/') && !url.starts_with("//") {
        return url.to_string();
    }
    // Allow absolute redirects to the configured auth public URL (e.g. https://auth.example.com)
    if let Some(base) = auth_public_url {
        let base = base.trim_end_matches('/');
        if !base.is_empty() && url.starts_with(base) {
            return url.to_string();
        }
    }
    // Reject everything else (external sites)
    "/login".to_string()
}
