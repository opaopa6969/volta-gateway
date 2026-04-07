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
}

impl ProxyService {
    pub fn new(volta: VoltaAuthClient, routing: Arc<RoutingTable>) -> Self {
        let backend_client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http();
        let flow_def = flow::build_proxy_flow(routing.clone());
        Self { volta, backend_client, routing, flow_def }
    }

    /// Handle a single request through the SM lifecycle.
    pub async fn handle(&self, req: Request<Incoming>) -> Response<BoxBody<Bytes, hyper::Error>> {
        let start = Instant::now();
        let request_id = uuid::Uuid::new_v4().to_string();
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

        // Log with SM transition info
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
