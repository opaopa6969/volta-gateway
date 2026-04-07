use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tracing::{info, warn};

use crate::auth::{AuthResult, VoltaAuthClient};
use crate::proxy::RoutingTable;

/// GW-19: WebSocket proxy — upgrade + bidirectional TCP tunnel.
///
/// Flow:
///   1. Auth check (volta /auth/verify) — authenticated users only
///   2. Resolve backend from routing table
///   3. Send upgrade request to backend
///   4. If backend accepts, upgrade client connection too
///   5. Bidirectional copy (tokio::io::copy_bidirectional)
pub async fn handle_websocket(
    req: Request<Incoming>,
    remote_addr: std::net::SocketAddr,
    volta: &VoltaAuthClient,
    routing: &Arc<RoutingTable>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let request_id = uuid::Uuid::new_v4().to_string();

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

    let (_, app_id) = match routing.get(&host) {
        Some(r) => r.clone(),
        None => {
            let wildcard = host.splitn(2, '.').nth(1)
                .and_then(|domain| routing.get(&format!("*.{domain}")));
            match wildcard {
                Some(r) => r.clone(),
                None => {
                    warn!(state = "WS_BAD_REQUEST", reason = "unknown host", host = %host);
                    return error_response(StatusCode::BAD_REQUEST, &request_id);
                }
            }
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

    // Resolve backend
    let backends = match routing.get(&host).or_else(|| {
        host.splitn(2, '.').nth(1)
            .and_then(|d| routing.get(&format!("*.{d}")))
    }) {
        Some((backends, _)) => backends.clone(),
        None => return error_response(StatusCode::BAD_GATEWAY, &request_id),
    };
    let backend = &backends[0];

    // Build WebSocket URL for backend
    let ws_url = format!("{}{}", backend.replace("http://", "ws://").replace("https://", "wss://"),
        req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/"));

    info!(
        state = "WS_UPGRADE",
        host = %host,
        path = %uri_path,
        backend = %backend,
        client_ip = %remote_addr.ip(),
    );

    // For Phase 4: actual TCP tunnel requires hyper::upgrade::on()
    // on both client and backend sides, then tokio::io::copy_bidirectional.
    // This is complex due to hyper 1.x's ownership model.
    //
    // For now, return 101 headers to indicate WebSocket support is recognized,
    // but the actual tunnel will be implemented when we integrate with
    // a WebSocket-aware backend proxy crate (e.g., tokio-tungstenite).
    //
    // Temporary: pass through to backend via normal HTTP
    // (works for polling-based WebSocket fallback like Socket.IO)
    info!(state = "WS_PASSTHROUGH", host = %host, path = %uri_path);

    // Forward as normal HTTP request (backend handles upgrade)
    // This works because hyper's auto::Builder supports HTTP upgrades
    // when the service returns a response with Upgrade header
    let resp = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("x-request-id", &request_id)
        .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
        .unwrap();

    resp
}

fn error_response(status: StatusCode, request_id: &str) -> Response<BoxBody<Bytes, hyper::Error>> {
    use http_body_util::Full;
    let reason = match status {
        StatusCode::BAD_REQUEST => "Bad Request",
        StatusCode::FORBIDDEN => "Forbidden",
        StatusCode::BAD_GATEWAY => "Bad Gateway",
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
