use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Incoming, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

use crate::auth::{AuthResult, VoltaAuthClient};
use crate::state::ProxyState;

/// Routing table: host → (backend_url, app_id)
pub type RoutingTable = HashMap<String, (String, Option<String>)>;

/// Core proxy service. Implements the SM lifecycle for each request.
///
/// SM pattern (sync judgment, async I/O):
///   RECEIVED → VALIDATED → ROUTED (sync)
///   → volta auth check (async)
///   → AUTH_CHECKED (sync judgment)
///   → backend forward (async)
///   → FORWARDED → COMPLETED (sync)
#[derive(Clone)]
pub struct ProxyService {
    volta: VoltaAuthClient,
    backend_client: Client<hyper_util::client::legacy::connect::HttpConnector, Incoming>,
    routing: Arc<RoutingTable>,
}

impl ProxyService {
    pub fn new(volta: VoltaAuthClient, routing: Arc<RoutingTable>) -> Self {
        let backend_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        Self { volta, backend_client, routing }
    }

    /// Update routing table (hot reload via SIGHUP).
    pub fn update_routing(&mut self, routing: Arc<RoutingTable>) {
        self.routing = routing;
    }

    /// Handle a single request through the SM lifecycle.
    pub async fn handle(&self, req: Request<Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
        let start = Instant::now();
        let request_id = uuid::Uuid::new_v4().to_string();
        let method = req.method().clone();
        let uri_path = req.uri().path().to_string();

        // ─── RECEIVED → VALIDATED (sync) ────────────────────
        let host = match extract_host(&req) {
            Some(h) => h,
            None => {
                warn!(state = "BAD_REQUEST", reason = "missing Host header");
                return error_response(StatusCode::BAD_REQUEST, &request_id);
            }
        };

        // Validate path
        if uri_path.contains("..") || uri_path.contains("//") {
            warn!(state = "BAD_REQUEST", reason = "invalid path", path = %uri_path);
            return error_response(StatusCode::BAD_REQUEST, &request_id);
        }

        // Header size check (approximate)
        let header_size: usize = req.headers().iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();
        if header_size > 8192 {
            warn!(state = "BAD_REQUEST", reason = "headers too large", size = header_size);
            return error_response(StatusCode::BAD_REQUEST, &request_id);
        }

        // ─── VALIDATED → ROUTED (sync) ──────────────────────
        let (backend_url, app_id) = match self.routing.get(&host) {
            Some(r) => r.clone(),
            None => {
                // Try wildcard: *.example.com
                let wildcard = host.splitn(2, '.').nth(1)
                    .and_then(|domain| self.routing.get(&format!("*.{domain}")));
                match wildcard {
                    Some(r) => r.clone(),
                    None => {
                        warn!(state = "BAD_REQUEST", reason = "unknown host", host = %host);
                        return error_response(StatusCode::BAD_REQUEST, &request_id);
                    }
                }
            }
        };

        // ─── ROUTED → AUTH_CHECKED (async: volta call) ──────
        let cookie = req.headers().get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let proto = if req.uri().scheme_str() == Some("https") { "https" } else { "http" };

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

        // ─── AUTH_CHECKED → FORWARDED (async: backend call) ─
        let target_uri = format!("{}{}", backend_url, req.uri().path_and_query()
            .map(|pq| pq.as_str()).unwrap_or("/"));

        let mut backend_req = Request::builder()
            .method(req.method())
            .uri(target_uri.parse::<Uri>().unwrap_or_default());

        // Copy original headers (except Host)
        for (name, value) in req.headers() {
            if name != "host" {
                backend_req = backend_req.header(name, value);
            }
        }

        // Inject X-Volta-* from auth
        for (key, value) in &volta_headers {
            backend_req = backend_req.header(key.as_str(), value.as_str());
        }

        // Add proxy headers
        backend_req = backend_req
            .header("X-Request-Id", &request_id)
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

        // ─── FORWARDED → COMPLETED (sync) ───────────────────
        let duration = start.elapsed();

        match backend_result {
            Ok(Ok(mut resp)) => {
                // Strip X-Volta-* from backend response (RP-16: forgery prevention)
                let headers = resp.headers_mut();
                let volta_keys: Vec<_> = headers.keys()
                    .filter(|k| k.as_str().starts_with("x-volta-"))
                    .cloned()
                    .collect();
                for key in volta_keys {
                    headers.remove(&key);
                }

                headers.insert("x-request-id", request_id.parse().unwrap());

                info!(
                    state = "COMPLETED",
                    method = %method,
                    host = %host,
                    path = %uri_path,
                    status = resp.status().as_u16(),
                    duration_ms = duration.as_millis() as u64,
                    user_id = volta_headers.get("x-volta-user-id").map(|s| s.as_str()).unwrap_or("-"),
                );

                Response::from(resp).map(|b| b.boxed())
            }
            Ok(Err(e)) => {
                warn!(state = "BAD_GATEWAY", reason = %e, host = %host, path = %uri_path);
                error_response(StatusCode::BAD_GATEWAY, &request_id)
            }
            Err(_) => {
                warn!(state = "GATEWAY_TIMEOUT", host = %host, path = %uri_path);
                error_response(StatusCode::GATEWAY_TIMEOUT, &request_id)
            }
        }
    }
}

fn extract_host(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
}

fn error_response(status: StatusCode, request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = Full::new(Bytes::from(format!(
        r#"{{"error":{{"code":"{}","request_id":"{}"}}}}"#,
        status.as_u16(), request_id
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
