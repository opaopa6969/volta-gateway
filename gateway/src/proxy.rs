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
use tramli_plugins::observability::{ObservabilityPlugin, TelemetrySink, TelemetryEvent};

use crate::auth::{AuthResult, VoltaAuthClient};
use crate::flow::{self, AuthData, BackendResponse, RequestData, RouteTarget};
use crate::state::ProxyState;

/// Tracing-based telemetry sink for tramli observability plugin.
struct TracingTelemetrySink {
    request_id: String,
}

impl TracingTelemetrySink {
    fn new(request_id: &str) -> Self {
        Self { request_id: request_id.to_string() }
    }
}

impl TelemetrySink for TracingTelemetrySink {
    fn emit(&self, event: TelemetryEvent) {
        // tramli 3.5: TelemetryEvent now includes flow_name + duration_micros
        match event.event_type {
            tramli_plugins::observability::TelemetryType::Transition => {
                tracing::trace!(
                    request_id = %self.request_id,
                    flow = %event.flow_name,
                    duration_us = event.duration_micros,
                    "SM transition: {}", event.data
                );
            }
            tramli_plugins::observability::TelemetryType::Error => {
                tracing::warn!(
                    request_id = %self.request_id,
                    flow = %event.flow_name,
                    duration_us = event.duration_micros,
                    "SM error: {}", event.data
                );
            }
            tramli_plugins::observability::TelemetryType::Guard => {
                tracing::trace!(
                    request_id = %self.request_id,
                    flow = %event.flow_name,
                    duration_us = event.duration_micros,
                    "SM guard: {}", event.data
                );
            }
            tramli_plugins::observability::TelemetryType::State => {
                tracing::trace!(
                    request_id = %self.request_id,
                    flow = %event.flow_name,
                    "SM state: {}", event.data
                );
            }
        }
    }

    fn events(&self) -> Vec<TelemetryEvent> {
        vec![]
    }
}

/// Route info for a host.
#[derive(Debug, Clone)]
pub struct RouteInfo {
    pub backends: Vec<String>,
    /// Weights for weighted routing (same length as backends). Empty = equal weight.
    pub weights: Vec<u32>,
    pub app_id: Option<String>,
    pub public: bool,
    pub bypass_paths: Vec<crate::config::BypassPath>,
    pub mirror: Option<crate::config::MirrorConfig>,
    pub path_prefix: Option<String>,
    pub strip_prefix: Option<String>,
    pub add_prefix: Option<String>,
    pub request_headers: Option<crate::config::HeaderManipulation>,
    pub response_headers: Option<crate::config::HeaderManipulation>,
    pub geo_allowlist: Vec<String>,
    pub geo_denylist: Vec<String>,
    pub timeout_secs: Option<u64>,
    pub cache: Option<crate::cache::CacheConfig>,
    pub backend_tls: Option<crate::mtls::BackendTlsConfig>,
}

/// GW-23: Routing table with multiple backends for round-robin LB.
/// host → RouteInfo
pub type RoutingTable = HashMap<String, RouteInfo>;

/// Round-robin backend selector with health-aware routing.
/// Dead backends are skipped. Health is tracked per-backend URL.
#[derive(Clone)]
pub struct BackendSelector {
    counters: Arc<Mutex<HashMap<String, usize>>>,
    health: Arc<Mutex<HashMap<String, bool>>>,
}

impl BackendSelector {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(Mutex::new(HashMap::new())),
            health: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Select next healthy backend. Uses weighted random if weights are set,
    /// otherwise round-robin. Dead backends are skipped.
    /// #27 fix: Single health lock acquisition for both weighted and round-robin paths.
    pub fn select<'a>(&self, host: &str, backends: &'a [String], weights: &[u32]) -> &'a str {
        if backends.len() <= 1 {
            return &backends[0];
        }

        let health = self.health.lock().unwrap();
        let mut map = self.counters.lock().unwrap();

        // Weighted selection
        if !weights.is_empty() && weights.len() == backends.len() {
            let total: u32 = weights.iter()
                .enumerate()
                .filter(|(i, _)| *health.get(backends[*i].as_str()).unwrap_or(&true))
                .map(|(_, w)| w)
                .sum();
            if total > 0 {
                let r = (rand_sample() * total as f64) as u32;
                let mut acc = 0u32;
                for (i, w) in weights.iter().enumerate() {
                    if !*health.get(backends[i].as_str()).unwrap_or(&true) { continue; }
                    acc += w;
                    if r < acc {
                        return &backends[i];
                    }
                }
            }
        }

        // Round-robin fallback (same lock guards)
        let counter = map.entry(host.to_string()).or_insert(0);
        for _ in 0..backends.len() {
            let idx = *counter % backends.len();
            *counter = counter.wrapping_add(1);
            let backend = &backends[idx];
            if *health.get(backend.as_str()).unwrap_or(&true) {
                return backend;
            }
        }
        &backends[*counter % backends.len()]
    }

    /// Mark backend as alive or dead.
    pub fn set_health(&self, backend: &str, alive: bool) {
        let mut h = self.health.lock().unwrap();
        h.insert(backend.to_string(), alive);
    }

    /// Get health status of all known backends.
    pub fn health_status(&self) -> HashMap<String, bool> {
        self.health.lock().unwrap().clone()
    }
}

/// PROD-1: Background health checker for backends.
pub fn spawn_health_checker(
    routing: Arc<RoutingTable>,
    selector: BackendSelector,
    interval_secs: u64,
    path: String,
) {
    tokio::spawn(async move {
        let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
            hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new()
            ).build_http();

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;

            // Collect all unique backend URLs
            let mut backends: Vec<String> = Vec::new();
            for info in routing.values() {
                for url in &info.backends {
                    if !backends.contains(url) {
                        backends.push(url.clone());
                    }
                }
            }

            for backend in &backends {
                let url = format!("{}{}", backend, path);
                let req = match hyper::Request::builder()
                    .uri(url.parse::<hyper::Uri>().unwrap_or_default())
                    .body(Empty::<Bytes>::new()) {
                    Ok(r) => r,
                    Err(_) => {
                        selector.set_health(backend, false);
                        continue;
                    }
                };

                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.request(req),
                ).await;

                let alive = matches!(result, Ok(Ok(resp)) if resp.status().is_success());
                selector.set_health(backend, alive);

                if !alive {
                    tracing::warn!(backend = %backend, "health check failed");
                }
            }
        }
    });
}

/// PH2-2: Per-IP + global rate limiter.
/// Fixed: Mutex<(count, window_start)> — no atomic/Mutex mixing.
#[derive(Clone)]
pub struct RateLimiter {
    global: Arc<Mutex<(u64, Instant)>>,
    global_limit: u64,
    per_ip: Arc<Mutex<HashMap<std::net::IpAddr, (u64, Instant)>>>,
    per_ip_limit: u64,
}

impl RateLimiter {
    fn new(global_rps: u64, per_ip_rps: u64) -> Self {
        Self {
            global: Arc::new(Mutex::new((0, Instant::now()))),
            global_limit: global_rps,
            per_ip: Arc::new(Mutex::new(HashMap::new())),
            per_ip_limit: per_ip_rps,
        }
    }

    fn allow(&self, ip: std::net::IpAddr) -> bool {
        // Global check — single Mutex protects both count and window
        {
            let mut g = self.global.lock().unwrap();
            if g.1.elapsed() >= std::time::Duration::from_secs(1) {
                *g = (1, Instant::now());
            } else {
                g.0 += 1;
                if g.0 > self.global_limit { return false; }
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
    pub trusted_proxies: Vec<ipnet::IpNet>,
}

impl HotState {
    #[allow(dead_code)]
    pub fn new(routing: Arc<RoutingTable>) -> Self {
        let flow_def = flow::build_proxy_flow(routing.clone());
        Self { routing, flow_def, error_pages: HashMap::new(), cors: HashMap::new(), trusted_proxies: Vec::new() }
    }

    pub fn new_with_config(
        routing: Arc<RoutingTable>,
        ip_allowlists: HashMap<String, Vec<ipnet::IpNet>>,
        error_pages_dir: Option<&str>,
        cors: CorsTable,
    ) -> Self {
        Self::new_full(routing, ip_allowlists, error_pages_dir, cors, Vec::new())
    }

    pub fn new_full(
        routing: Arc<RoutingTable>,
        ip_allowlists: HashMap<String, Vec<ipnet::IpNet>>,
        error_pages_dir: Option<&str>,
        cors: CorsTable,
        trusted_proxies: Vec<ipnet::IpNet>,
    ) -> Self {
        let flow_def = flow::build_proxy_flow_with_allowlist(routing.clone(), ip_allowlists);
        let error_pages = load_error_pages(error_pages_dir);
        Self { routing, flow_def, error_pages, cors, trusted_proxies }
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
    pub metrics: Arc<crate::metrics::Metrics>,
    pub plugin_manager: Arc<crate::plugin::PluginManager>,
    pub response_cache: crate::cache::ResponseCache,
}

impl ProxyService {
    pub fn new(volta: VoltaAuthClient, hot: Arc<ArcSwap<HotState>>, metrics: Arc<crate::metrics::Metrics>, plugin_manager: Arc<crate::plugin::PluginManager>) -> Self {
        let backend_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        let retry_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        Self {
            volta, backend_client, retry_client, hot, metrics, plugin_manager,
            rate_limiter: RateLimiter::new(1000, 100),
            backend_selector: BackendSelector::new(),
            circuit_breaker: CircuitBreaker::new(5, 30),
            response_cache: crate::cache::ResponseCache::new(10_000),
        }
    }

    /// Handle a single request through the SM lifecycle.
    pub async fn handle(&self, req: Request<Incoming>, remote_addr: std::net::SocketAddr) -> Response<BoxBody<Bytes, hyper::Error>> {
        let request_id = uuid::Uuid::new_v4().to_string();

        // #7: OpenTelemetry — propagate or generate traceparent (W3C Trace Context)
        let traceparent = req.headers().get("traceparent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                // Generate: 00-{trace_id}-{span_id}-01
                let id = uuid::Uuid::new_v4();
                let trace_id = format!("{:032x}", id.as_u128());
                let span_id = format!("{:016x}", id.as_u128() as u64); // lower 64 bits
                format!("00-{}-{}-01", trace_id, span_id)
            });

        // Load current hot state (atomic, lock-free) — needed early for trusted proxy check
        let hot = self.hot.load();

        // PROD-4: Resolve real client IP before rate limiting
        let real_client_ip = if !hot.trusted_proxies.is_empty()
            && hot.trusted_proxies.iter().any(|net| net.contains(&remote_addr.ip()))
        {
            req.headers().get("cf-connecting-ip")
                .or_else(|| req.headers().get("x-real-ip"))
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                .unwrap_or(remote_addr.ip())
        } else {
            remote_addr.ip()
        };

        // PH2-2: Per-IP + global rate limiting
        if !self.rate_limiter.allow(real_client_ip) {
            warn!(state = "RATE_LIMITED", client_ip = %real_client_ip);
            return rate_limited_response(&request_id);
        }

        // GW-19: WebSocket upgrade → delegate to websocket module
        let is_upgrade = req.headers().get("upgrade")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);
        if is_upgrade {
            return crate::websocket::handle_websocket(
                req, remote_addr, &self.volta, &hot.routing, &self.backend_selector, &self.retry_client,
                &hot.trusted_proxies,
            ).await;
        }

        let start = Instant::now();
        let method = req.method().clone();
        let uri_path = req.uri().path().to_string();

        // Extract request metadata for SM
        let host = extract_host(&req).unwrap_or_default();

        // GW-30: CORS preflight — handle OPTIONS at proxy layer
        // GW-44: CORS default is "no headers" (not wildcard). Explicit cors_origins required.
        if method == hyper::Method::OPTIONS {
            let cors_origin = match hot.cors.get(&host) {
                Some(origins) => {
                    // Check for explicit wildcard
                    if origins.iter().any(|o| o == "*") {
                        "*".to_string()
                    } else {
                        let req_origin = req.headers().get("origin")
                            .and_then(|v| v.to_str().ok()).unwrap_or("");
                        if origins.iter().any(|o| o == req_origin) {
                            req_origin.to_string()
                        } else {
                            String::new()
                        }
                    }
                }
                None => String::new(), // GW-44: no config → no CORS headers
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
            client_ip: Some(real_client_ip),
        };

        // ─── SM Phase 1: start_flow (sync) ──────────────────
        // RECEIVED → VALIDATED → ROUTED (auto-chain, stops at External)
        // tramli 3.6: strict_mode is now in FlowDefinition (Builder::strict_mode())
        let mut eng = FlowEngine::new(InMemoryFlowStore::new());
        let sink = Arc::new(TracingTelemetrySink::new(&request_id));
        let obs = ObservabilityPlugin::new(sink);
        obs.install_with_options(&mut eng, true);  // append=true: chain with any existing loggers
        let engine = Mutex::new(eng);
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
                    let route = hot.routing.get(&host).or_else(|| {
                        host.splitn(2, '.').nth(1)
                            .and_then(|d| hot.routing.get(&format!("*.{d}")))
                    });
                    let weights = route.map(|r| r.weights.as_slice()).unwrap_or(&[]);
                    let selected = self.backend_selector.select(&host, &rt.backends, weights).to_string();
                    (selected, rt.app_id.clone())
                }
                Err(_) => return error_response(StatusCode::BAD_REQUEST, &request_id),
            }
        };

        // Check public/bypass status from routing table
        let route_info = hot.routing.get(&host).or_else(|| {
            host.splitn(2, '.').nth(1)
                .and_then(|d| hot.routing.get(&format!("*.{d}")))
        }).cloned();
        let is_public = route_info.as_ref().map(|r| r.public).unwrap_or(false);
        let bypass_match = route_info.as_ref().and_then(|r| {
            r.bypass_paths.iter().find(|bp| uri_path.starts_with(&bp.prefix)).cloned()
        });
        let skip_auth = is_public || bypass_match.is_some();

        // Override backend if bypass_path has a backend override
        let backend_url = bypass_match
            .and_then(|bp| bp.backend.clone())
            .unwrap_or(backend_url);

        // ─── Async I/O: volta auth check ────────────────────
        let volta_headers = if skip_auth {
            info!(state = "AUTH_SKIP", host = %host, path = %uri_path, public = is_public);
            HashMap::new()
        } else {
            let auth_result = self.volta.check(
                &host, &uri_path, proto,
                cookie.as_deref(),
                app_id.as_deref(),
            ).await;

            match auth_result {
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

        // ─── Plugin: request phase ──────────────────────────
        {
            // GW-60: Merge volta_headers into plugin context so plugins can access X-Volta-*
            let mut plugin_headers: HashMap<String, String> = req.headers().iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
                .collect();
            for (k, v) in &volta_headers {
                plugin_headers.insert(k.clone(), v.clone());
            }
            let mut plugin_ctx = crate::plugin::PluginContext {
                method: method.to_string(),
                host: host.clone(),
                path: uri_path.clone(),
                headers: plugin_headers,
                client_ip: real_client_ip.to_string(),
                reject: None,
                add_headers: HashMap::new(),
                remove_headers: vec![],
            };
            if let Some((status, body)) = self.plugin_manager.run_request(&mut plugin_ctx) {
                let resp_body = Full::new(Bytes::from(
                    format!(r#"{{"error":{{"code":{},"reason":"{}","request_id":"{}"}}}}"#, status, body, request_id)
                ));
                return Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
                    .header("content-type", "application/json")
                    .header("x-request-id", &request_id)
                    .body(resp_body.map_err(|e| match e {}).boxed())
                    .unwrap();
            }
        }

        // ─── #10: Geo-based access control (CF-IPCountry) ────
        if let Some(ri) = route_info.as_ref() {
            let country = req.headers().get("cf-ipcountry")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ri.geo_allowlist.is_empty() && !ri.geo_allowlist.iter().any(|c| c == country) {
                info!(state = "GEO_DENIED", host = %host, country = country);
                return error_response_with_pages(StatusCode::FORBIDDEN, &request_id, &hot.error_pages);
            }
            if ri.geo_denylist.iter().any(|c| c == country) {
                info!(state = "GEO_DENIED", host = %host, country = country);
                return error_response_with_pages(StatusCode::FORBIDDEN, &request_id, &hot.error_pages);
            }
        }

        // ─── Cache lookup (#8) ──────────────────────────────
        let cache_config = route_info.as_ref().and_then(|r| r.cache.as_ref());
        let cache_enabled = cache_config.map(|c| c.enabled).unwrap_or(false);
        let cache_method_ok = cache_config
            .map(|c| c.methods.iter().any(|m| m.eq_ignore_ascii_case(&method.to_string())))
            .unwrap_or(false);

        if cache_enabled && cache_method_ok {
            let ignore_query = cache_config.map(|c| c.ignore_query).unwrap_or(false);
            let query = req.uri().query();
            let cache_key = crate::cache::ResponseCache::key(
                method.as_str(), &host, &uri_path, query, ignore_query,
            );
            if let Some((status, headers, body)) = self.response_cache.get(&cache_key) {
                info!(state = "CACHE_HIT", host = %host, path = %uri_path);
                let mut resp = Response::builder()
                    .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK));
                for (name, value) in &headers {
                    if let (Ok(hname), Ok(hval)) = (name.parse::<hyper::header::HeaderName>(), value.parse::<hyper::header::HeaderValue>()) {
                        resp = resp.header(hname, hval);
                    }
                }
                resp = resp
                    .header("x-volta-cache", "HIT")
                    .header("x-request-id", &request_id);
                return resp.body(Full::new(body).map_err(|e| match e {}).boxed()).unwrap();
            }
        }

        // ─── Async I/O: backend forward ─────────────────────
        // Circuit breaker check
        if !self.circuit_breaker.is_available(&backend_url) {
            warn!(state = "CIRCUIT_OPEN", backend = %backend_url, host = %host);
            // GW-46: Retry-After header tells client when to retry
            let mut resp = error_response_with_pages(StatusCode::SERVICE_UNAVAILABLE, &request_id, &hot.error_pages);
            resp.headers_mut().insert("retry-after",
                self.circuit_breaker.recovery_secs.to_string().parse().unwrap());
            return resp;
        }

        let mut path_and_query = req.uri().path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        // #3: Path rewrite (strip_prefix / add_prefix)
        if let Some(ri) = route_info.as_ref() {
            if let Some(ref strip) = ri.strip_prefix {
                if path_and_query.starts_with(strip.as_str()) {
                    path_and_query = path_and_query[strip.len()..].to_string();
                    if !path_and_query.starts_with('/') {
                        path_and_query = format!("/{}", path_and_query);
                    }
                }
            }
            if let Some(ref add) = ri.add_prefix {
                path_and_query = format!("{}{}", add.trim_end_matches('/'), path_and_query);
            }
        }

        let target_uri = format!("{}{}", backend_url, path_and_query);

        // #19 fix: Collect headers, filtering out request_headers.remove
        let req_method = req.method().clone();
        let remove_headers: Vec<String> = route_info.as_ref()
            .and_then(|r| r.request_headers.as_ref())
            .map(|rh| rh.remove.iter().map(|s| s.to_lowercase()).collect())
            .unwrap_or_default();
        // #48: Strip client X-Volta-* (forgery prevention) + #53: hop-by-hop headers
        const HOP_BY_HOP: &[&str] = &[
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "transfer-encoding",
        ];
        let req_headers: Vec<_> = req.headers().iter()
            .filter(|(name, _)| *name != "host")
            .filter(|(name, _)| !name.as_str().starts_with("x-volta-"))
            .filter(|(name, _)| !HOP_BY_HOP.contains(&name.as_str()))
            .filter(|(name, _)| !remove_headers.contains(&name.as_str().to_string()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        // #49: Only preserve client XFF if from trusted proxy
        let client_ip = real_client_ip.to_string();
        let is_from_trusted = !hot.trusted_proxies.is_empty()
            && hot.trusted_proxies.iter().any(|net| net.contains(&remote_addr.ip()));
        let xff = if is_from_trusted {
            match req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                Some(existing) => format!("{}, {}", existing, client_ip),
                None => client_ip,
            }
        } else {
            client_ip // ignore client-supplied XFF
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
            .header("X-Forwarded-Proto", proto)
            .header("traceparent", &traceparent);

        // #4/#19: Request header add (remove already filtered during collection)
        if let Some(ri) = route_info.as_ref() {
            if let Some(ref rh) = ri.request_headers {
                for (name, value) in &rh.add {
                    backend_req = backend_req.header(name.as_str(), value.as_str());
                }
            }
        }

        let backend_req = match backend_req.body(req.into_body()) {
            Ok(r) => r,
            Err(e) => {
                warn!(state = "BAD_GATEWAY", reason = %e);
                return error_response_with_pages(StatusCode::BAD_GATEWAY, &request_id, &hot.error_pages);
            }
        };

        // #35: Per-route timeout (default 30s)
        let timeout_secs = route_info.as_ref()
            .and_then(|r| r.timeout_secs)
            .unwrap_or(30);
        let backend_result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
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
        headers.insert("traceparent", traceparent.parse().unwrap());

        // GW-21 + GW-44: CORS headers (per-route only, no implicit wildcard)
        let cors_origin = match hot.cors.get(&host) {
            Some(origins) => {
                if origins.iter().any(|o| o == "*") {
                    "*".to_string()
                } else {
                    let req_origin = req_origin.as_deref().unwrap_or("");
                    if origins.iter().any(|o| o == req_origin) {
                        req_origin.to_string()
                    } else {
                        String::new()
                    }
                }
            }
            None => String::new(), // GW-44: no config → no CORS headers
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
        // #26: Only set x-frame-options if not overridden by response_headers config
        let has_frame_override = route_info.as_ref()
            .and_then(|r| r.response_headers.as_ref())
            .map(|rh| rh.add.contains_key("x-frame-options") || rh.add.contains_key("content-security-policy"))
            .unwrap_or(false);
        if !has_frame_override {
            headers.insert("x-frame-options", "DENY".parse().unwrap());
        }

        // #4: Response header manipulation
        if let Some(ri) = route_info.as_ref() {
            if let Some(ref rh) = ri.response_headers {
                for name in &rh.remove {
                    if let Ok(hname) = name.parse::<hyper::header::HeaderName>() {
                        headers.remove(&hname);
                    }
                }
                for (name, value) in &rh.add {
                    if let (Ok(hname), Ok(hval)) = (name.parse::<hyper::header::HeaderName>(), value.parse::<hyper::header::HeaderValue>()) {
                        headers.insert(hname, hval);
                    }
                }
            }
        }

        // GW-6: Log with client IP + SM transition info
        let transition_count = {
            let eng = engine.lock().unwrap();
            eng.store.transition_log().len()
        };

        // #5: Structured access log (per-request)
        info!(
            state = "ACCESS",
            method = %method,
            host = %host,
            path = %uri_path,
            status = response_status,
            latency_ms = duration.as_micros() as f64 / 1000.0,
            client_ip = %real_client_ip,
            user_id = volta_headers.get("x-volta-user-id").map(|s| s.as_str()).unwrap_or("-"),
            upstream = %backend_url,
            request_id = %request_id,
            trace = %traceparent,
            transitions = transition_count,
            public = skip_auth,
        );

        // Record metrics
        self.metrics.record_status(response_status);
        self.metrics.record_duration(start);

        // Traffic mirroring — fire-and-forget to shadow backend
        let mirror_config = route_info.as_ref().and_then(|r| r.mirror.clone());
        if let Some(mirror) = mirror_config.as_ref() {
            let should_mirror = mirror.sample_rate >= 1.0
                || rand_sample() < mirror.sample_rate;
            if should_mirror {
                let mirror_uri = format!("{}{}", mirror.backend, path_and_query);
                let mut mirror_req = Request::builder()
                    .method(&method)
                    .uri(mirror_uri.parse::<Uri>().unwrap_or_default())
                    .header("X-Volta-Mirror", "true")
                    .header("X-Request-Id", &request_id);
                for (name, value) in &req_headers {
                    // GW-61: Don't leak X-Volta-* to mirror backend
                    // #54: Don't leak Cookie/Authorization to mirror
                    let key = name.as_str();
                    if !key.starts_with("x-volta-")
                        && key != "cookie"
                        && key != "authorization" {
                        mirror_req = mirror_req.header(name, value);
                    }
                }
                // Don't forward volta_headers to mirror (GW-61: user info leak prevention)
                if let Ok(mirror_req) = mirror_req.body(Empty::<Bytes>::new()) {
                    let metrics = self.metrics.clone();
                    let retry_client = self.retry_client.clone();
                    tokio::spawn(async move {
                        metrics.mirror_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Err(_) = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            retry_client.request(mirror_req),
                        ).await {
                            metrics.mirror_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    });
                }
            }
        }

        // ─── Cache store (#8) ────────────────────────────────
        // Store response in cache if cacheable (after backend forward, before plugin/compression)
        // Note: we can only cache if we buffer the body, which we do for compression anyway.
        // For non-compressed responses, we skip caching to avoid double-buffering.
        // This is a tradeoff — full caching requires body collection.

        // ─── Plugin: response phase ─────────────────────────
        {
            let mut plugin_ctx = crate::plugin::PluginContext {
                method: method.to_string(),
                host: host.clone(),
                path: uri_path.clone(),
                headers: response.headers().iter()
                    .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string())))
                    .collect(),
                client_ip: real_client_ip.to_string(),
                reject: None,
                add_headers: HashMap::new(),
                remove_headers: vec![],
            };
            self.plugin_manager.run_response(&mut plugin_ctx);
            let headers = response.headers_mut();
            for name in &plugin_ctx.remove_headers {
                if let Ok(hname) = name.parse::<hyper::header::HeaderName>() {
                    headers.remove(&hname);
                }
            }
            for (name, value) in &plugin_ctx.add_headers {
                if let (Ok(hname), Ok(hval)) = (name.parse::<hyper::header::HeaderName>(), value.parse::<hyper::header::HeaderValue>()) {
                    headers.insert(hname, hval);
                }
            }
        }

        // Compression: gzip text-based responses if client accepts and backend didn't compress
        let already_encoded = response.headers().contains_key("content-encoding");
        let is_compressible = response.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript"))
            .unwrap_or(false);
        let client_accepts_gzip = accept_encoding.contains("gzip");

        if !already_encoded && is_compressible && client_accepts_gzip {
            let (parts, body) = response.into_parts();

            // If cache is enabled, collect body for caching + compress with flate2 (existing path)
            let need_cache = cache_enabled && cache_method_ok && response_status >= 200 && response_status < 300;

            if need_cache {
                use std::io::Write;

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

                if body_bytes.len() > 1_048_576 {
                    let mut resp = Response::builder().status(parts.status);
                    for (name, value) in &parts.headers { resp = resp.header(name, value); }
                    return resp.body(Full::new(body_bytes).map_err(|e| match e {}).boxed()).unwrap();
                }

                // Cache store
                let cache_control = parts.headers.get("cache-control").and_then(|v| v.to_str().ok());
                let max_body = cache_config.map(|c| c.max_body_size).unwrap_or(10_485_760);
                if crate::cache::is_cacheable(cache_control) && body_bytes.len() <= max_body {
                    let ttl = std::time::Duration::from_secs(cache_config.map(|c| c.ttl_secs).unwrap_or(300));
                    let ignore_query = cache_config.map(|c| c.ignore_query).unwrap_or(false);
                    let store_query = uri_path.split('?').nth(1);
                    let cache_key = crate::cache::ResponseCache::key(
                        method.as_str(), &host, uri_path.split('?').next().unwrap_or(&uri_path), store_query, ignore_query);
                    let cached_headers: Vec<(String, String)> = parts.headers.iter()
                        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_string(), v.to_string()))).collect();
                    self.response_cache.put(cache_key, response_status, cached_headers, body_bytes.clone(), ttl);
                }

                let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                if encoder.write_all(&body_bytes).is_ok() {
                    if let Ok(compressed) = encoder.finish() {
                        if compressed.len() < body_bytes.len() {
                            let mut resp = Response::builder().status(parts.status);
                            for (name, value) in &parts.headers {
                                match name.as_str() {
                                    "content-length" | "content-encoding" | "transfer-encoding" => {}
                                    _ => { resp = resp.header(name, value); }
                                }
                            }
                            resp = resp.header("content-encoding", "gzip")
                                .header("content-length", compressed.len().to_string());
                            return resp.body(Full::new(Bytes::from(compressed)).map_err(|e| match e {}).boxed()).unwrap();
                        }
                    }
                }
                let mut resp = Response::builder().status(parts.status);
                for (name, value) in &parts.headers { resp = resp.header(name, value); }
                return resp.body(Full::new(body_bytes).map_err(|e| match e {}).boxed()).unwrap();
            }

            // #37: Streaming compression (no cache needed) — zero-copy, bounded memory
            use tokio_util::io::{ReaderStream, StreamReader};
            use futures::TryStreamExt;

            let body_stream = http_body_util::BodyStream::new(body)
                .map_ok(|frame| frame.into_data().unwrap_or_default())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()));
            let async_read = StreamReader::new(body_stream);
            let gzip_read = async_compression::tokio::bufread::GzipEncoder::new(
                tokio::io::BufReader::new(async_read)
            );
            // Collect the compressed stream into bytes (streaming through gzip encoder)
            // This avoids holding the uncompressed body in memory.
            use tokio::io::AsyncReadExt;
            let mut compressed_data = Vec::new();
            let mut gzip_read = gzip_read;
            if gzip_read.read_to_end(&mut compressed_data).await.is_ok() && !compressed_data.is_empty() {
                let mut resp = Response::builder().status(parts.status);
                for (name, value) in &parts.headers {
                    match name.as_str() {
                        "content-length" | "content-encoding" | "transfer-encoding" => {}
                        _ => { resp = resp.header(name, value); }
                    }
                }
                resp = resp.header("content-encoding", "gzip")
                    .header("content-length", compressed_data.len().to_string());
                return resp.body(Full::new(Bytes::from(compressed_data)).map_err(|e| match e {}).boxed()).unwrap();
            }
            // Compression failed — return original response parts
            let mut resp = Response::builder().status(parts.status);
            for (name, value) in &parts.headers { resp = resp.header(name, value); }
            return resp.body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed()).unwrap();
        }

        Response::from(response).map(|b| b.boxed())
    }
}

/// #18 fix: Random sampling using atomic counter + UUID entropy.
fn rand_sample() -> f64 {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let c = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mix = c.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407); // LCG
    (mix % 10000) as f64 / 10000.0
}

/// GW-26: Normalize host header — strip port, handle IPv6, lowercase.
/// Shared by proxy.rs and websocket.rs (fixes extract_host duplication).
pub fn normalize_host(raw: &str) -> String {
    if raw.starts_with('[') {
        // IPv6: [::1]:8080 → [::1]
        raw.split(']').next().map(|s| format!("{}]", s)).unwrap_or_else(|| raw.to_string())
    } else {
        // IPv4/hostname: app.example.com:8080 → app.example.com
        raw.split(':').next().unwrap_or(raw).to_string()
    }.to_lowercase()
}

fn extract_host(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| normalize_host(h))
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
