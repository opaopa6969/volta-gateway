use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::copy_bidirectional;
use tracing::{error, info, warn};

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
    ws_client: &Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    trusted_proxies: &[ipnet::IpNet],
    assertion_signer: Option<&crate::assertion::GatewayAssertionSigner>,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let request_id = uuid::Uuid::new_v4().to_string();

    // GW-37: WebSocket connection limit
    let current = WS_CONNECTIONS.load(Ordering::Relaxed);
    if current >= MAX_WS_CONNECTIONS {
        warn!(
            state = "WS_LIMIT",
            current = current,
            max = MAX_WS_CONNECTIONS
        );
        return error_response(StatusCode::SERVICE_UNAVAILABLE, &request_id);
    }

    // Extract host (shared normalize_host function)
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|h| crate::proxy::normalize_host(h))
        .unwrap_or_default();

    let uri_path = req.uri().path().to_string();

    // Auth check — WebSocket must be authenticated
    let cookie = req
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Authorization: Bearer <token>
    //
    // ここが無かったので、既存の M2M / OIDC アクセストークンを持っていても
    // gateway 配下のサービスには入れなかった。scheme の比較は大文字小文字を
    // 無視する（RFC 7235 §2.1）。
    let bearer = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            let (scheme, rest) = s.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
        })
        .filter(|t| !t.is_empty());

    let route = match resolve_route(routing, &host) {
        Some(r) => r,
        None => {
            warn!(state = "WS_BAD_REQUEST", reason = "unknown host", host = %host);
            return error_response(StatusCode::BAD_REQUEST, &request_id);
        }
    };
    // Public routes skip auth; bypass_paths also skip for matching prefixes
    let bypass_match = route
        .bypass_paths
        .iter()
        .find(|bp| crate::proxy::bypass_path_matches(&uri_path, &bp.prefix));
    let skip_auth = route.public || bypass_match.is_some();
    let is_soft_auth = route.soft_auth;
    let min_role = route.min_role.as_deref();

    if route.public && min_role.is_some() {
        // `public: true` と `min_role` の併用は意味衝突するため fail-closed。
        // 通常は validation で弾かれるが、動的ルーティング更新で後から入り得る
        // ので実行時にも拒否する。
        warn!(
            state = "WS_DENIED",
            host = %host,
            "min_role cannot be combined with public route"
        );
        return error_response(StatusCode::FORBIDDEN, &request_id);
    }
    // `bypass_paths` + `min_role` は併用可能 (#126): bypass path に当たった
    // リクエストは認証ごと skip し `min_role` も適用しない。

    let volta_headers = if !skip_auth {
        if is_soft_auth {
            // #71: soft-auth — try auth, but never reject. On success inject
            // X-Volta-*; on failure/missing session pass through anonymously.
            let real_client_ip = if !trusted_proxies.is_empty()
                && trusted_proxies
                    .iter()
                    .any(|net| net.contains(&remote_addr.ip()))
            {
                req.headers()
                    .get("cf-connecting-ip")
                    .or_else(|| req.headers().get("x-real-ip"))
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .unwrap_or(remote_addr.ip())
            } else {
                remote_addr.ip()
            };
            let client_ip_str = real_client_ip.to_string();
            let auth = volta
                .check_with_degraded_policy(
                    &host,
                    &uri_path,
                    "https",
                    cookie.as_deref(),
                    route.app_id.as_deref(),
                    min_role,
                    Some(&client_ip_str),
                    bearer.as_deref(),
                    true, // soft-auth: always allow degraded fallback (fail-open)
                )
                .await;
            match auth {
                AuthResult::Authenticated(headers) => {
                    info!(state = "WS_SOFT_AUTH_OK", host = %host);
                    headers
                }
                AuthResult::Redirect(_) | AuthResult::Denied | AuthResult::Error(_) => {
                    info!(state = "WS_SOFT_AUTH_ANON", host = %host);
                    HashMap::new()
                }
            }
        } else {
            let real_client_ip = if !trusted_proxies.is_empty()
                && trusted_proxies
                    .iter()
                    .any(|net| net.contains(&remote_addr.ip()))
            {
                req.headers()
                    .get("cf-connecting-ip")
                    .or_else(|| req.headers().get("x-real-ip"))
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<std::net::IpAddr>().ok())
                    .unwrap_or(remote_addr.ip())
            } else {
                remote_addr.ip()
            };
            let client_ip_str = real_client_ip.to_string();
            let auth = volta
                .check_with_degraded_policy(
                    &host,
                    &uri_path,
                    "https",
                    cookie.as_deref(),
                    route.app_id.as_deref(),
                    min_role,
                    Some(&client_ip_str),
                    bearer.as_deref(),
                    min_role.is_none(),
                )
                .await;
            match auth {
                AuthResult::Authenticated(headers) => headers,
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
        }
    } else {
        HashMap::new()
    };

    if let Some(min_role) = min_role {
        if bypass_match.is_some() {
            // bypass path に当たったリクエストは認証ごと skip し `min_role` も適用しない (#126)。
            // `route.public` + `min_role` の組み合わせは前段で 403 return 済み。
        } else {
            let required = min_role.trim().to_ascii_uppercase();
            let policy = volta_auth_core::policy::PolicyEngine::default_policy();
            let valid_role = policy.hierarchy().iter().any(|role| role == &required);
            let roles: Vec<String> = volta_headers
                .get("x-volta-roles")
                .map(|value| {
                    value
                        .split(',')
                        .map(|role| role.trim().to_ascii_uppercase())
                        .filter(|role| !role.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            if !valid_role
                || !matches!(
                    policy.enforce_min_role(&roles, &required),
                    volta_auth_core::policy::PolicyResult::Allow
                )
            {
                return error_response(StatusCode::FORBIDDEN, &request_id);
            }
        }
    }

    // Select backend — check bypass_path backend override first
    let bypass_backend = bypass_match.and_then(|bp| bp.backend.clone());

    // Select backend (round-robin, or bypass override)
    let weights = route.weights.as_slice();
    let backend = bypass_backend.unwrap_or_else(|| {
        backend_selector
            .select(&host, &route.backends, weights)
            .to_string()
    });

    // Build backend upgrade request
    let backend_uri = format!(
        "{}{}",
        backend,
        req.uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
    );

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

    // #50: Resolve real client IP (same as proxy.rs PROD-4)
    let real_client_ip = if !trusted_proxies.is_empty()
        && trusted_proxies
            .iter()
            .any(|net| net.contains(&remote_addr.ip()))
    {
        req.headers()
            .get("cf-connecting-ip")
            .or_else(|| req.headers().get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .unwrap_or(remote_addr.ip())
    } else {
        remote_addr.ip()
    };

    // Forward relevant headers (#48: strip X-Volta-* from client)
    // HTTP/2 (RFC 8441) pseudo-headers (:protocol, :method, etc.) are filtered out.
    // HTTP/2 CONNECT lacks Upgrade/Connection headers, so we add them for the
    // HTTP/1.1 backend Upgrade handshake.
    let is_h2_connect = req.method() == hyper::Method::CONNECT;
    let has_upgrade = req.headers().contains_key("upgrade");
    for (name, value) in req.headers() {
        let key = name.as_str();
        match key {
            "host" | ":method" | ":protocol" | ":scheme" | ":path" | ":authority" => {}
            _ if key.starts_with("x-volta-") => {} // #48: strip client X-Volta-*
            "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol"
            | "sec-websocket-extensions"
            | "cookie"
            | "authorization" => {
                backend_req = backend_req.header(name, value);
            }
            _ if key.starts_with("x-") => {
                backend_req = backend_req.header(name, value);
            }
            _ => {}
        }
    }
    // HTTP/2 CONNECT → HTTP/1.1 Upgrade: synthesize Upgrade/Connection headers
    if is_h2_connect && !has_upgrade {
        backend_req = backend_req
            .header("upgrade", "websocket")
            .header("connection", "upgrade");
    }
    for (name, value) in &volta_headers {
        backend_req = backend_req.header(name, value);
    }
    backend_req = backend_req
        .header("X-Request-Id", &request_id)
        .header("X-Forwarded-For", real_client_ip.to_string())
        .header("X-Forwarded-Host", &host)
        .header("X-Forwarded-Proto", "https");

    if let Some(signer) = assertion_signer {
        let path_with_query = req
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/");
        let assertion = signer.sign_now(
            "GET",
            path_with_query,
            volta_headers
                .get("x-volta-user-id")
                .map(String::as_str)
                .unwrap_or(""),
            volta_headers
                .get("x-volta-tenant-id")
                .map(String::as_str)
                .unwrap_or(""),
            volta_headers
                .get("x-volta-roles")
                .map(String::as_str)
                .unwrap_or(""),
        );
        backend_req = backend_req
            .header(crate::assertion::KEY_ID_HEADER, assertion.key_id)
            .header(crate::assertion::TIMESTAMP_HEADER, assertion.timestamp)
            .header(crate::assertion::SIGNATURE_HEADER, assertion.signature);
    }

    let backend_req = match backend_req.body(Empty::<Bytes>::new()) {
        Ok(r) => r,
        Err(e) => {
            warn!(state = "WS_BAD_GATEWAY", reason = %e);
            return error_response(StatusCode::BAD_GATEWAY, &request_id);
        }
    };

    // #20 fix: Use shared client instead of per-connection client
    let backend_resp = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        ws_client.request(backend_req),
    )
    .await
    {
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

    // Build response for client, forwarding backend's WebSocket headers.
    // HTTP/1.1: 101 Switching Protocols. HTTP/2 (RFC 8441): 200 OK.
    let client_status = if is_h2_connect {
        StatusCode::OK
    } else {
        StatusCode::SWITCHING_PROTOCOLS
    };
    let mut client_resp = Response::builder()
        .status(client_status)
        .header("x-request-id", &request_id);

    for (name, value) in backend_resp.headers() {
        let key = name.as_str();
        match key {
            "upgrade"
            | "connection"
            | "sec-websocket-accept"
            | "sec-websocket-protocol"
            | "sec-websocket-extensions" => {
                // HTTP/2 CONNECT: Upgrade/Connection are HTTP/1.1 hop-by-hop,
                // but Sec-WebSocket-* are fine to forward.
                if is_h2_connect && (key == "upgrade" || key == "connection") {
                    continue;
                }
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

fn resolve_route(routing: &RoutingTable, host: &str) -> Option<crate::proxy::RouteInfo> {
    routing.get(host).cloned().or_else(|| {
        host.splitn(2, '.')
            .nth(1)
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
        status.as_u16(),
        reason,
        request_id
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
