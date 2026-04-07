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

/// Routing table: host → (backend_url, app_id)
pub type RoutingTable = HashMap<String, (String, Option<String>)>;

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

/// Core proxy service. Drives each request through the tramli SM engine.
///
/// B-pattern: sync SM judgment + async I/O outside.
///   start_flow (sync, ~1μs) → volta auth (async) → resume (sync) → backend (async) → resume (sync)
#[derive(Clone)]
pub struct ProxyService {
    volta: VoltaAuthClient,
    backend_client: Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
    pub routing: Arc<RoutingTable>,
    flow_def: Arc<FlowDefinition<ProxyState>>,
    pub rate_limiter: RateLimiter,
}

impl ProxyService {
    pub fn new(volta: VoltaAuthClient, routing: Arc<RoutingTable>) -> Self {
        let backend_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        let flow_def = flow::build_proxy_flow(routing.clone());
        Self { volta, backend_client, routing, flow_def, rate_limiter: RateLimiter::new(1000, 100) }
    }

    /// Handle a single request through the SM lifecycle.
    pub async fn handle(&self, req: Request<Incoming>, remote_addr: std::net::SocketAddr) -> Response<BoxBody<Bytes, hyper::Error>> {
        let request_id = uuid::Uuid::new_v4().to_string();

        // PH2-2: Per-IP + global rate limiting
        if !self.rate_limiter.allow(remote_addr.ip()) {
            warn!(state = "RATE_LIMITED", client_ip = %remote_addr.ip());
            return rate_limited_response(&request_id);
        }

        let start = Instant::now();
        let method = req.method().clone();
        let uri_path = req.uri().path().to_string();

        // Extract request metadata for SM
        let host = extract_host(&req).unwrap_or_default();
        let header_size: usize = req.headers().iter()
            .map(|(k, v)| k.as_str().len() + v.len()).sum();
        let content_length = req.headers().get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());
        let cookie = req.headers().get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let proto = if req.uri().scheme_str() == Some("https") { "https" } else { "http" };

        let req_data = RequestData {
            host: host.clone(),
            path: uri_path.clone(),
            method: method.to_string(),
            header_size,
            content_length,
        };

        // ─── SM Phase 1: start_flow (sync) ──────────────────
        // RECEIVED → VALIDATED → ROUTED (auto-chain, stops at External)
        let engine = Mutex::new(FlowEngine::new(InMemoryFlowStore::new()));
        let flow_id = {
            let mut eng = engine.lock().unwrap();
            let initial_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
                (TypeId::of::<RequestData>(), Box::new(req_data)),
            ];
            match eng.start_flow(self.flow_def.clone(), &request_id, initial_data) {
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
                Ok(rt) => (rt.backend_url.clone(), rt.app_id.clone()),
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
                return error_response(StatusCode::FORBIDDEN, &request_id);
            }
            AuthResult::Error(msg) => {
                warn!(state = "BAD_GATEWAY", reason = %msg, host = %host);
                return error_response(StatusCode::BAD_GATEWAY, &request_id);
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
                return error_response(StatusCode::BAD_GATEWAY, &request_id);
            }
        }

        // ─── Async I/O: backend forward ─────────────────────
        let target_uri = format!("{}{}", backend_url, req.uri().path_and_query()
            .map(|pq| pq.as_str()).unwrap_or("/"));

        let mut backend_req = Request::builder()
            .method(req.method())
            .uri(target_uri.parse::<Uri>().unwrap_or_default());

        for (name, value) in req.headers() {
            if name != "host" {
                backend_req = backend_req.header(name, value);
            }
        }
        for (key, value) in &volta_headers {
            backend_req = backend_req.header(key.as_str(), value.as_str());
        }
        // X-Forwarded-For: append client IP to existing chain
        let client_ip = remote_addr.ip().to_string();
        let xff = match req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            Some(existing) => format!("{}, {}", existing, client_ip),
            None => client_ip,
        };

        backend_req = backend_req
            .header("X-Request-Id", &request_id)
            .header("X-Forwarded-For", &xff)
            .header("X-Forwarded-Host", &host)
            .header("X-Forwarded-Proto", proto);

        let backend_req = match backend_req.body(req.into_body()) {
            Ok(r) => r,
            Err(e) => {
                warn!(state = "BAD_GATEWAY", reason = %e);
                return error_response(StatusCode::BAD_GATEWAY, &request_id);
            }
        };

        let backend_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.backend_client.request(backend_req),
        ).await;

        // ─── SM Phase 3: resume with backend response (sync) ─
        let (response_status, mut response) = match backend_result {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                (status, resp)
            }
            Ok(Err(e)) => {
                warn!(state = "BAD_GATEWAY", reason = %e, host = %host, path = %uri_path);
                return error_response(StatusCode::BAD_GATEWAY, &request_id);
            }
            Err(_) => {
                warn!(state = "GATEWAY_TIMEOUT", host = %host, path = %uri_path);
                return error_response(StatusCode::GATEWAY_TIMEOUT, &request_id);
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

        Response::from(response).map(|b| b.boxed())
    }
}

fn extract_host(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
}

fn error_response(status: StatusCode, request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    // GW-2: Generic reason for client (detailed reason goes to server log only)
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
