use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::copy_bidirectional;
use tracing::{info, warn, error};

use crate::auth::{AuthResult, VoltaAuthClient};
use crate::proxy::{BackendSelector, RoutingTable};

/// GW-37: Global WebSocket connection counter + limit
static WS_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
const MAX_WS_CONNECTIONS: usize = 1024;

/// GW-19: WebSocket proxy — upgrade + bidirectional TCP tunnel.
///
/// Flow:
///   1. Auth check (volta /auth/verify)
///   2. Resolve backend from routing table
///   3. Forward upgrade request to backend
///   4. If backend accepts (101), upgrade client side too
///   5. Bidirectional copy (tokio::io::copy_bidirectional)
pub async fn handle_websocket(
    req: Request<Incoming>,
    remote_addr: std::net::SocketAddr,
    volta: &VoltaAuthClient,
    routing: &Arc<RoutingTable>,
    backend_selector: &BackendSelector,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let request_id = uuid::Uuid::new_v4().to_string();

    // GW-37: WebSocket connection limit
    let current = WS_CONNECTIONS.load(Ordering::Relaxed);
    if current >= MAX_WS_CONNECTIONS {
        warn!(state = "WS_LIMIT", current = current, max = MAX_WS_CONNECTIONS);
        return error_response(StatusCode::SERVICE_UNAVAILABLE, &request_id);
    }

    // Extract host
    let host = req.headers().get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            if h.starts_with('[') {
                h.split(']').next().map(|s| format!("{}]", s)).unwrap_or_else(|| h.to_string())
            } else {
                h.split(':').next().unwrap_or(h).to_string()
            }.to_lowercase()
        })
        .unwrap_or_default();

    let uri_path = req.uri().path().to_string();

    // Auth check — WebSocket must be authenticated
    let cookie = req.headers().get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let (backends, app_id) = match resolve_backend(routing, &host) {
        Some(r) => r,
        None => {
            warn!(state = "WS_BAD_REQUEST", reason = "unknown host", host = %host);
            return error_response(StatusCode::BAD_REQUEST, &request_id);
        }
    };

    let auth = volta.check(&host, &uri_path, "https", cookie.as_deref(), app_id.as_deref()).await;
    match auth {
        AuthResult::Authenticated(_) => {}
        AuthResult::Redirect(loc) => {
            info!(state = "WS_REDIRECT", host = %host);
            return redirect_response(&loc, &request_id);
        }
        AuthResult::Denied => {
            return error_response(StatusCode::FORBIDDEN, &request_id);
        }
        AuthResult::Error(msg) => {
            warn!(state = "WS_BAD_GATEWAY", reason = %msg);
            return error_response(StatusCode::BAD_GATEWAY, &request_id);
        }
    }

    // Select backend (round-robin)
    let backend = backend_selector.select(&backends).to_string();

    // Build backend upgrade request
    let backend_uri = format!("{}{}", backend,
        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));

    info!(
        state = "WS_UPGRADE",
        host = %host,
        path = %uri_path,
        backend = %backend,
        client_ip = %remote_addr.ip(),
    );

    // Connect to backend with upgrade request
    let mut backend_req = Request::builder()
        .method("GET")
        .uri(backend_uri.parse::<Uri>().unwrap_or_default());

    // Forward relevant headers
    for (name, value) in req.headers() {
        let key = name.as_str();
        match key {
            "host" => {} // skip — backend gets its own host
            "upgrade" | "connection" | "sec-websocket-key"
            | "sec-websocket-version" | "sec-websocket-protocol"
            | "sec-websocket-extensions" | "cookie" | "authorization" => {
                backend_req = backend_req.header(name, value);
            }
            _ if key.starts_with("x-") => {
                backend_req = backend_req.header(name, value);
            }
            _ => {}
        }
    }
    backend_req = backend_req
        .header("X-Request-Id", &request_id)
        .header("X-Forwarded-For", remote_addr.ip().to_string())
        .header("X-Forwarded-Host", &host)
        .header("X-Forwarded-Proto", "https");

    let backend_req = match backend_req.body(Empty::<Bytes>::new()) {
        Ok(r) => r,
        Err(e) => {
            warn!(state = "WS_BAD_GATEWAY", reason = %e);
            return error_response(StatusCode::BAD_GATEWAY, &request_id);
        }
    };

    // Send upgrade request to backend
    let backend_client: Client<_, Empty<Bytes>> = Client::builder(TokioExecutor::new())
        .build_http();

    let backend_resp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        backend_client.request(backend_req),
    ).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            warn!(state = "WS_BAD_GATEWAY", reason = %e, backend = %backend);
            return error_response(StatusCode::BAD_GATEWAY, &request_id);
        }
        Err(_) => {
            warn!(state = "WS_GATEWAY_TIMEOUT", backend = %backend);
            return error_response(StatusCode::GATEWAY_TIMEOUT, &request_id);
        }
    };

    // Backend must respond with 101 Switching Protocols
    if backend_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        warn!(
            state = "WS_BACKEND_REJECT",
            status = backend_resp.status().as_u16(),
            backend = %backend,
        );
        return error_response(StatusCode::BAD_GATEWAY, &request_id);
    }

    // Build 101 response for client, forwarding backend's WebSocket headers
    let mut client_resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("x-request-id", &request_id);

    for (name, value) in backend_resp.headers() {
        let key = name.as_str();
        match key {
            "upgrade" | "connection" | "sec-websocket-accept"
            | "sec-websocket-protocol" | "sec-websocket-extensions" => {
                client_resp = client_resp.header(name, value);
            }
            _ => {}
        }
    }

    let client_resp = client_resp
        .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
        .unwrap();

    // GW-37: Track WebSocket connection
    WS_CONNECTIONS.fetch_add(1, Ordering::Relaxed);

    // Spawn TCP tunnel: upgrade both sides and copy bidirectionally
    let req_id = request_id.clone();
    let host_log = host.clone();
    tokio::spawn(async move {
        // Ensure connection counter is decremented when tunnel ends
        struct WsGuard;
        impl Drop for WsGuard {
            fn drop(&mut self) {
                WS_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let _guard = WsGuard;

        // Upgrade backend connection
        let backend_upgraded = match hyper::upgrade::on(backend_resp).await {
            Ok(u) => u,
            Err(e) => {
                error!(state = "WS_TUNNEL_FAIL", side = "backend", reason = %e, request_id = %req_id);
                return;
            }
        };

        // Upgrade client connection
        let client_upgraded = match hyper::upgrade::on(req).await {
            Ok(u) => u,
            Err(e) => {
                error!(state = "WS_TUNNEL_FAIL", side = "client", reason = %e, request_id = %req_id);
                return;
            }
        };

        let mut client_io = TokioIo::new(client_upgraded);
        let mut backend_io = TokioIo::new(backend_upgraded);

        match copy_bidirectional(&mut client_io, &mut backend_io).await {
            Ok((client_to_backend, backend_to_client)) => {
                info!(
                    state = "WS_TUNNEL_CLOSED",
                    host = %host_log,
                    request_id = %req_id,
                    client_to_backend = client_to_backend,
                    backend_to_client = backend_to_client,
                );
            }
            Err(e) => {
                // Normal: peer closed connection
                let msg = e.to_string();
                if msg.contains("reset") || msg.contains("broken pipe") || msg.contains("closed") {
                    info!(state = "WS_TUNNEL_CLOSED", host = %host_log, request_id = %req_id);
                } else {
                    warn!(state = "WS_TUNNEL_ERROR", reason = %e, request_id = %req_id);
                }
            }
        }
    });

    client_resp
}

fn resolve_backend(routing: &RoutingTable, host: &str) -> Option<(Vec<String>, Option<String>)> {
    routing.get(host).cloned().or_else(|| {
        host.splitn(2, '.').nth(1)
            .and_then(|d| routing.get(&format!("*.{d}")).cloned())
    })
}

fn error_response(status: StatusCode, request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
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
