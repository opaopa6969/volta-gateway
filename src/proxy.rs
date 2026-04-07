use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Incoming, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::any::TypeId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{info, warn};

use tramli::{FlowDefinition, FlowEngine, InMemoryFlowStore, CloneAny};

use crate::auth::{AuthResult, VoltaAuthClient};
use crate::flow::{self, AuthData, BackendResponse, RequestData, RouteTarget};
use crate::state::ProxyState;

/// GW-23: Routing table with multiple backends for round-robin LB.
/// host → (backend_urls, app_id)
pub type RoutingTable = HashMap<String, (Vec<String>, Option<String>)>;

/// Round-robin backend selector.
#[derive(Clone)]
pub struct BackendSelector {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl BackendSelector {
    pub fn new() -> Self {
        Self { counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)) }
    }

    pub fn select<'a>(&self, backends: &'a [String]) -> &'a str {
        if backends.len() <= 1 {
            return &backends[0];
        }
        let idx = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % backends.len();
        &backends[idx]
    }
}

/// PH2-2: Per-IP + global rate limiter.
#[derive(Clone)]
pub struct RateLimiter {
    global_count: Arc<std::sync::atomic::AtomicU64>,
    global_limit: u64,
    global_window: Arc<Mutex<Instant>>,
    per_ip: Arc<Mutex<HashMap<std::net::IpAddr, (u64, Instant)>>>,
    per_ip_limit: u64,
}

impl RateLimiter {
    fn new(global_rps: u64, per_ip_rps: u64) -> Self {
        Self {
            global_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            global_limit: global_rps,
            global_window: Arc::new(Mutex::new(Instant::now())),
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            per_ip_limit: per_ip_rps,
        }
    }

    fn allow(&self, ip: std::net::IpAddr) -> bool {
        // Global check
        {
            let mut start = self.global_window.lock().unwrap();
            if start.elapsed() >= std::time::Duration::from_secs(1) {
                *start = Instant::now();
                self.global_count.store(1, std::sync::atomic::Ordering::SeqCst);
            } else {
                let current = self.global_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if current >= self.global_limit { return false; }
            }
        }

        // Per-IP check
        {
            let mut map = self.per_ip.lock().unwrap();
            let entry = map.entry(ip).or_insert((0, Instant::now()));
            if entry.1.elapsed() >= std::time::Duration::from_secs(1) {
                *entry = (1, Instant::now());
            } else {
                entry.0 += 1;
                if entry.0 > self.per_ip_limit { return false; }
            }
        }

        true
    }

    /// GC: remove IP entries idle for > ttl.
    pub fn gc(&self, ttl: std::time::Duration) {
        let mut map = self.per_ip.lock().unwrap();
        map.retain(|_, (_, last)| last.elapsed() < ttl);
    }
}

/// Pre-loaded error pages: status code → HTML content.
pub type ErrorPages = HashMap<u16, String>;

/// CORS origins table: host → allowed origins. Empty map entry = use wildcard "*".
pub type CorsTable = HashMap<String, Vec<String>>;

/// Hot-swappable state: routing table + flow definition + error pages + CORS config.
/// Rebuilt on SIGHUP and atomically swapped via ArcSwap.
pub struct HotState {
    pub routing: Arc<RoutingTable>,
    pub flow_def: Arc<FlowDefinition<ProxyState>>,
    pub error_pages: ErrorPages,
    pub cors: CorsTable,
}

impl HotState {
    pub fn new(routing: Arc<RoutingTable>) -> Self {
        let flow_def = flow::build_proxy_flow(routing.clone());
        Self { routing, flow_def, error_pages: HashMap::new(), cors: HashMap::new() }
    }

    pub fn new_with_config(
        routing: Arc<RoutingTable>,
        ip_allowlists: HashMap<String, Vec<ipnet::IpNet>>,
        error_pages_dir: Option<&str>,
        cors: CorsTable,
    ) -> Self {
        let flow_def = flow::build_proxy_flow_with_allowlist(routing.clone(), ip_allowlists);
        let error_pages = load_error_pages(error_pages_dir);
        Self { routing, flow_def, error_pages, cors }
    }
}

/// Load HTML error pages from directory. Files named like 502.html, 403.html.
fn load_error_pages(dir: Option<&str>) -> ErrorPages {
    let mut pages = HashMap::new();
    let dir = match dir {
        Some(d) => d,
        None => return pages,
    };
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return pages,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("html") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if let Ok(code) = stem.parse::<u16>() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        pages.insert(code, content);
                    }
                }
            }
        }
    }
    if !pages.is_empty() {
        tracing::info!(count = pages.len(), dir = dir, "loaded custom error pages");
    }
    pages
}

/// Per-backend circuit breaker.
#[derive(Clone)]
pub struct CircuitBreaker {
    /// backend_url → (failure_count, last_failure_time, state)
    backends: Arc<Mutex<HashMap<String, CircuitState>>>,
    /// Failures before opening circuit
    threshold: u32,
    /// How long to keep circuit open before trying half-open
    recovery_secs: u64,
}

struct CircuitState {
    failures: u32,
    last_failure: Instant,
    open: bool,
}

impl CircuitBreaker {
    fn new(threshold: u32, recovery_secs: u64) -> Self {
        Self {
            backends: Arc::new(Mutex::new(HashMap::new())),
            threshold,
            recovery_secs,
        }
    }

    /// Returns true if the backend is available (closed or half-open).
    fn is_available(&self, backend: &str) -> bool {
        let map = self.backends.lock().unwrap();
        match map.get(backend) {
            None => true,
            Some(state) => {
                if !state.open { return true; }
                // Half-open: allow one request after recovery period
                state.last_failure.elapsed() >= std::time::Duration::from_secs(self.recovery_secs)
            }
        }
    }

    /// Record a successful request — reset circuit.
    fn record_success(&self, backend: &str) {
        let mut map = self.backends.lock().unwrap();
        map.remove(backend);
    }

    /// Record a failure — may open circuit.
    fn record_failure(&self, backend: &str) {
        let mut map = self.backends.lock().unwrap();
        let state = map.entry(backend.to_string()).or_insert(CircuitState {
            failures: 0,
            last_failure: Instant::now(),
            open: false,
        });
        state.failures += 1;
        state.last_failure = Instant::now();
        if state.failures >= self.threshold {
            state.open = true;
        }
    }
}

/// Core proxy service. Drives each request through the tramli SM engine.
///
/// B-pattern: sync SM judgment + async I/O outside.
///   start_flow (sync, ~1μs) → volta auth (async) → resume (sync) → backend (async) → resume (sync)
#[derive(Clone)]
pub struct ProxyService {
    volta: VoltaAuthClient,
    backend_client: Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
    retry_client: Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    pub hot: Arc<ArcSwap<HotState>>,
    pub rate_limiter: RateLimiter,
    pub backend_selector: BackendSelector,
    circuit_breaker: CircuitBreaker,
}

impl ProxyService {
    pub fn new(volta: VoltaAuthClient, hot: Arc<ArcSwap<HotState>>) -> Self {
        let backend_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        let retry_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        Self {
            volta, backend_client, retry_client, hot,
            rate_limiter: RateLimiter::new(1000, 100),
            backend_selector: BackendSelector::new(),
            circuit_breaker: CircuitBreaker::new(5, 30),
        }
    }

    /// Handle a single request through the SM lifecycle.
    pub async fn handle(&self, req: Request<Incoming>, remote_addr: std::net::SocketAddr) -> Response<BoxBody<Bytes, hyper::Error>> {
        let request_id = uuid::Uuid::new_v4().to_string();

        // PH2-2: Per-IP + global rate limiting
        if !self.rate_limiter.allow(remote_addr.ip()) {
            warn!(state = "RATE_LIMITED", client_ip = %remote_addr.ip());
            return rate_limited_response(&request_id);
        }

        // Load current hot state (atomic, lock-free)
        let hot = self.hot.load();

        // GW-19: WebSocket upgrade → delegate to websocket module
        let is_upgrade = req.headers().get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        if is_upgrade {
            return crate::websocket::handle_websocket(
                req, remote_addr, &self.volta, &hot.routing, &self.backend_selector,
            ).await;
        }

        let start = Instant::now();
        let method = req.method().clone();
        let uri_path = req.uri().path().to_string();

        // Extract request metadata for SM
        let host = extract_host(&req).unwrap_or_default();

        // GW-30: CORS preflight — handle OPTIONS at proxy layer
        if method == hyper::Method::OPTIONS {
            let cors_origin = match hot.cors.get(&host) {
                Some(origins) => {
                    let req_origin = req.headers().get("origin")
                        .and_then(|v| v.to_str().ok()).unwrap_or("");
                    if origins.iter().any(|o| o == req_origin) {
                        req_origin.to_string()
                    } else {
                        String::new()
                    }
                }
                None => "*".to_string(),
            };
            if !cors_origin.is_empty() {
                let mut resp = Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .header("access-control-allow-origin", &cors_origin)
                    .header("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
                    .header("access-control-allow-headers", "Content-Type, Authorization, X-CSRF-Token")
                    .header("access-control-max-age", "86400")
                    .header("x-request-id", &request_id);
                if cors_origin != "*" {
                    resp = resp.header("vary", "Origin");
                }
                return resp.body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed()).unwrap();
            }
        }
        let header_size: usize = req.headers().iter()
            .map(|(k, v)| k.as_str().len() + v.len()).sum();
        let content_length = req.headers().get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cookie = req.headers().get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let req_origin = req.headers().get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let accept_encoding = req.headers().get("accept-encoding")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let proto = if req.uri().scheme_str() == Some("https") { "https" } else { "http" };

        let req_data = RequestData {
            host: host.clone(),
            path: uri_path.clone(),
            method: method.to_string(),
            header_size,
            content_length,
            client_ip: Some(remote_addr.ip()),
        };

        // ─── SM Phase 1: start_flow (sync) ──────────────────
        // RECEIVED → VALIDATED → ROUTED (auto-chain, stops at External)
        let engine = Mutex::new(FlowEngine::new(InMemoryFlowStore::new()));
        let flow_id = {
            let mut eng = engine.lock().unwrap();
            let initial_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
                (TypeId::of::<RequestData>(), Box::new(req_data)),
            ];
            match eng.start_flow(hot.flow_def.clone(), &request_id, initial_data) {
                Ok(id) => id,
                Err(e) => {
                    warn!(state = "BAD_REQUEST", reason = %e, host = %host);
                    return error_response(StatusCode::BAD_REQUEST, &request_id);
                }
            }
        };

        // SM should be in ROUTED state now (waiting for External: auth check)
        // Extract route target from SM context
        let (backend_url, app_id) = {
            let eng = engine.lock().unwrap();
            let flow = match eng.store.get(&flow_id) {
                Some(f) => f,
                None => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &request_id),
            };
            match flow.context.get::<RouteTarget>() {
                Ok(rt) => {
                    let selected = self.backend_selector.select(&rt.backends).to_string();
                    (selected, rt.app_id.clone())
                }
                Err(_) => return error_response(StatusCode::BAD_REQUEST, &request_id),
            }
        };

        // ─── Async I/O: volta auth check ────────────────────
        let auth_result = self.volta.check(
            &host, &uri_path, proto,
            cookie.as_deref(),
            app_id.as_deref(),
        ).await;

        let volta_headers = match auth_result {
            AuthResult::Authenticated(headers) => headers,
            AuthResult::Redirect(location) => {
                info!(state = "REDIRECT", host = %host, path = %uri_path, location = %location);
                return redirect_response(&location, &request_id);
            }
            AuthResult::Denied => {
                info!(state = "DENIED", host = %host, path = %uri_path);
                return error_response_with_pages(StatusCode::FORBIDDEN, &request_id, &hot.error_pages);
            }
            AuthResult::Error(msg) => {
                warn!(state = "BAD_GATEWAY", reason = %msg, host = %host);
                return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages);
            }
        };

        // ─── SM Phase 2: resume with auth data (sync) ───────
        {
            let mut eng = engine.lock().unwrap();
            let auth_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
                (TypeId::of::<AuthData>(), Box::new(AuthData { volta_headers: volta_headers.clone() })),
            ];
            if let Err(e) = eng.resume_and_execute(&flow_id, auth_data) {
                warn!(state = "BAD_GATEWAY", reason = %e, host = %host);
                return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages);
            }
        }

        // ─── Async I/O: backend forward ─────────────────────
        // Circuit breaker check
        if !self.circuit_breaker.is_available(&backend_url) {
            warn!(state = "CIRCUIT_OPEN", backend = %backend_url, host = %host);
            return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages);
        }

        let path_and_query = req.uri().path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let target_uri = format!("{}{}", backend_url, path_and_query);

        // Collect headers for potential retry
        let req_method = req.method().clone();
        let req_headers: Vec<_> = req.headers().iter()
            .filter(|(name, _)| *name != "host")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let client_ip = remote_addr.ip().to_string();
        let xff = match req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(existing) => format!("{}, {}", existing, client_ip),
            None => client_ip,
        };

        let is_idempotent = matches!(req_method.as_str(), "GET" | "HEAD" | "OPTIONS");
        let max_retries = if is_idempotent { 2u32 } else { 0 };

        let mut backend_req = Request::builder()
            .method(&req_method)
            .uri(target_uri.parse::<Uri>().unwrap_or_default());
        for (name, value) in &req_headers {
            backend_req = backend_req.header(name, value);
        }
        for (key, value) in &volta_headers {
            backend_req = backend_req.header(key.as_str(), value.as_str());
        }
        backend_req = backend_req
            .header("X-Request-Id", &request_id)
            .header("X-Forwarded-For", &xff)
            .header("X-Forwarded-Host", &host)
            .header("X-Forwarded-Proto", proto);

        let backend_req = match backend_req.body(req.into_body()) {
            Ok(r) => r,
            Err(e) => {
                warn!(state = "BAD_GATEWAY", reason = %e);
                return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages);
            }
        };

        let backend_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.backend_client.request(backend_req),
        ).await;

        // Retry on connection error for idempotent requests (body already consumed)
        let backend_result = match &backend_result {
            Ok(Err(_)) if max_retries > 0 => {
                self.circuit_breaker.record_failure(&backend_url);
                info!(state = "RETRY", attempt = 1, backend = %backend_url);
                // Rebuild request (no body for idempotent methods)
                let mut retry_req = Request::builder()
                    .method(&req_method)
                    .uri(format!("{}{}", backend_url, path_and_query).parse::<Uri>().unwrap_or_default());
                for (name, value) in &req_headers {
                    retry_req = retry_req.header(name, value);
                }
                for (key, value) in &volta_headers {
                    retry_req = retry_req.header(key.as_str(), value.as_str());
                }
                retry_req = retry_req
                    .header("X-Request-Id", &request_id)
                    .header("X-Forwarded-For", &xff)
                    .header("X-Forwarded-Host", &host)
                    .header("X-Forwarded-Proto", proto);
                let retry_req = retry_req
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    self.retry_client.request(retry_req),
                ).await
            }
            _ => backend_result,
        };

        // ─── SM Phase 3: resume with backend response (sync) ─
        let (response_status, mut response) = match backend_result {
            Ok(Ok(resp)) => {
                self.circuit_breaker.record_success(&backend_url);
                let status = resp.status().as_u16();
                (status, resp)
            }
            Ok(Err(e)) => {
                self.circuit_breaker.record_failure(&backend_url);
                warn!(state = "BAD_GATEWAY", reason = %e, host = %host, path = %uri_path);
                return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages);
            }
            Err(_) => {
                self.circuit_breaker.record_failure(&backend_url);
                warn!(state = "GATEWAY_TIMEOUT", host = %host, path = %uri_path);
                return error_response_with_pages(StatusCode::GATEWAY_TIMEOUT, &request_id, &hot.error_pages);
            }
        };

        {
            let mut eng = engine.lock().unwrap();
            let resp_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
                (TypeId::of::<BackendResponse>(), Box::new(BackendResponse { status: response_status })),
            ];
            let _ = eng.resume_and_execute(&flow_id, resp_data);
        }

        // ─── Response processing ────────────────────────────
        let duration = start.elapsed();

        // Strip X-Volta-* from backend response (RP-16: forgery prevention)
        let headers = response.headers_mut();
        let volta_keys: Vec<_> = headers.keys()
            .filter(|k| k.as_str().starts_with("x-volta-"))
            .cloned().collect();
        for key in volta_keys {
            headers.remove(&key);
        }
        headers.insert("x-request-id", request_id.parse().unwrap());

        // GW-21: CORS headers (per-route or wildcard)
        let cors_origin = match hot.cors.get(&host) {
            Some(origins) => {
                // Check if request Origin matches any allowed origin
                let req_origin = req_origin.as_deref().unwrap_or("");
                if origins.iter().any(|o| o == req_origin) {
                    req_origin.to_string()
                } else {
                    // Origin not allowed — don't set CORS headers
                    String::new()
                }
            }
            None => "*".to_string(), // No per-route config → wildcard
        };
        if !cors_origin.is_empty() {
            headers.insert("access-control-allow-origin", cors_origin.parse().unwrap());
            headers.insert("access-control-allow-methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS".parse().unwrap());
            headers.insert("access-control-allow-headers", "Content-Type, Authorization, X-CSRF-Token".parse().unwrap());
            if cors_origin != "*" {
                headers.insert("vary", "Origin".parse().unwrap());
            }
        }

        // GW-4: Security response headers
        headers.insert("strict-transport-security",
            "max-age=31536000; includeSubDomains".parse().unwrap());
        headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        headers.insert("x-frame-options", "DENY".parse().unwrap());

        // GW-6: Log with client IP + SM transition info
        let transition_count = {
            let eng = engine.lock().unwrap();
            eng.store.transition_log().len()
        };

        info!(
            state = "COMPLETED",
            method = %method,
            host = %host,
            path = %uri_path,
            status = response_status,
            duration_ms = duration.as_millis() as u64,
            transitions = transition_count,
            client_ip = %remote_addr.ip(),
            user_id = volta_headers.get("x-volta-user-id").map(|s| s.as_str()).unwrap_or("-"),
        );

        // Compression: gzip text-based responses if client accepts and backend didn't compress
        let already_encoded = response.headers().contains_key("content-encoding");
        let is_compressible = response.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript"))
            .unwrap_or(false);
        let client_accepts_gzip = accept_encoding.contains("gzip");

        if !already_encoded && is_compressible && client_accepts_gzip {
            use std::io::Write;

            // GW-36 fix: preserve all original headers via into_parts()
            let (parts, body) = response.into_parts();

            // GW-28: skip compression for large responses (> 1MB) to avoid OOM
            let content_len = parts.headers.get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok());
            if content_len.map_or(false, |len| len > 1_048_576) {
                let response = Response::from_parts(parts, body);
                return Response::from(response).map(|b| b.boxed());
            }

            let body_bytes = match http_body_util::BodyExt::collect(body).await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages),
            };

            let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            if encoder.write_all(&body_bytes).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    if compressed.len() < body_bytes.len() {
                        // Rebuild response preserving all original headers
                        let mut resp = Response::builder().status(parts.status);
                        for (name, value) in &parts.headers {
                            // Skip headers that compression changes
                            match name.as_str() {
                                "content-length" | "content-encoding" | "transfer-encoding" => {}
                                _ => { resp = resp.header(name, value); }
                            }
                        }
                        resp = resp
                            .header("content-encoding", "gzip")
                            .header("content-length", compressed.len().to_string());

                        let body = Full::new(Bytes::from(compressed));
                        return resp.body(body.map_err(|e| match e {}).boxed()).unwrap();
                    }
                }
            }
            // Compression failed or didn't help — return uncompressed with original headers
            let mut resp = Response::builder().status(parts.status);
            for (name, value) in &parts.headers {
                resp = resp.header(name, value);
            }
            let body = Full::new(body_bytes);
            return resp.body(body.map_err(|e| match e {}).boxed()).unwrap();
        }

        Response::from(response).map(|b| b.boxed())
    }
}

/// GW-26: Extract host, handling IPv6 literals like [::1]:8080
fn extract_host(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            if h.starts_with('[') {
                // IPv6: [::1]:8080 → [::1]
                h.split(']').next().map(|s| format!("{}]", s)).unwrap_or_else(|| h.to_string())
            } else {
                // IPv4/hostname: app.example.com:8080 → app.example.com
                h.split(':').next().unwrap_or(h).to_string()
            }.to_lowercase()
        })
}

fn error_response(status: StatusCode, request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    error_response_with_pages(status, request_id, &HashMap::new())
}

fn error_response_with_pages(
    status: StatusCode,
    request_id: &str,
    error_pages: &ErrorPages,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    // Check for custom HTML error page
    if let Some(html) = error_pages.get(&status.as_u16()) {
        let body = Full::new(Bytes::from(html.clone()));
        return Response::builder()
            .status(status)
            .header("content-type", "text/html; charset=utf-8")
            .header("x-request-id", request_id)
            .body(body.map_err(|e| match e {}).boxed())
            .unwrap();
    }

    // GW-2: JSON fallback
    let reason = match status {
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::BAD_GATEWAY => "Bad Gateway",
        StatusCode::GATEWAY_TIMEOUT => "Gateway Timeout",
        _ => "Internal Server Error",
    };
    let body = Full::new(Bytes::from(format!(
        r#"{{"error":{{"code":{},"reason":"{}","request_id":"{}"}}}}"#,
        status.as_u16(), reason, request_id
    )));
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("x-request-id", request_id)
        .body(body.map_err(|e| match e {}).boxed())
        .unwrap()
}

fn redirect_response(location: &str, request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(StatusCode::FOUND)
        .header("location", location)
        .header("x-request-id", request_id)
        .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
        .unwrap()
}

fn rate_limited_response(request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from(format!(
        r#"{{"error":{{"code":429,"reason":"Too Many Requests","request_id":"{}"}}}}"#,
        request_id
    )));
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("content-type", "application/json")
        .header("retry-after", "1")
        .header("x-request-id", request_id)
        .body(body.map_err(|e| match e {}).boxed())
        .unwrap()
}
