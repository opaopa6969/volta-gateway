//! Integration tests: real HTTP requests through volta-gateway proxy.
//!
//! Each test spins up:
//!   - Mock backend (echo server)
//!   - Mock volta-auth-server
//!   - volta-gateway ProxyService
//!
//! Then sends real HTTP requests and asserts responses.

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;

use volta_gateway::auth::{AuthResult, VoltaAuthClient};
use volta_gateway::config::AuthConfig;
use volta_gateway::proxy::{HotState, ProxyService, RoutingTable};

type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

fn full_body(bytes: Bytes) -> BoxBody {
    Full::new(bytes).map_err(|e| match e {}).boxed()
}

fn empty_body() -> BoxBody {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

/// Start a mock HTTP server, returns (addr, join_handle).
async fn mock_server(
    handler: impl Fn(Request<Incoming>) -> Response<BoxBody> + Send + Sync + Clone + 'static,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let resp = handler(req);
                    async move { Ok::<_, hyper::Error>(resp) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    (addr, handle)
}

/// Create a ProxyService wired to mock auth + mock backend.
fn make_proxy(auth_addr: SocketAddr, backend_addr: SocketAddr, host: &str) -> ProxyService {
    let auth_config = AuthConfig {
        volta_url: format!("http://{}", auth_addr),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2000,
        pool_max_idle: 4,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
        jwt_issuer: None,
        jwt_audience: None,
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        host.to_string(),
        volta_gateway::proxy::RouteInfo {
            weights: vec![],
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("test-app".into()),
            public: false,
            soft_auth: false,
            min_role: None,
            bypass_paths: vec![],
            auth_rules: vec![],
            mirror: None,
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        },
    );

    let hot = Arc::new(ArcSwap::from_pointee(HotState::new(Arc::new(routing))));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    let plugins = Arc::new(volta_gateway::plugin::PluginManager::new());
    let signer = volta_gateway::assertion::GatewayAssertionSigner::new_with_key_id(
        "2026-08",
        "0123456789abcdef0123456789abcdef",
    )
    .unwrap();
    ProxyService::new_with_assertion(volta, hot, metrics, plugins, Some(signer))
}

fn make_proxy_with_cors(
    auth_addr: SocketAddr,
    backend_addr: SocketAddr,
    host: &str,
    origins: Vec<String>,
) -> ProxyService {
    let auth_config = AuthConfig {
        volta_url: format!("http://{}", auth_addr),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2000,
        pool_max_idle: 4,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
        jwt_issuer: None,
        jwt_audience: None,
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        host.to_string(),
        volta_gateway::proxy::RouteInfo {
            min_role: None,
            weights: vec![],
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("test-app".into()),
            public: false,
            soft_auth: false,
            bypass_paths: vec![],
            auth_rules: vec![],
            mirror: None,
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        },
    );

    let mut cors = HashMap::new();
    cors.insert(host.to_string(), origins);

    let hot = Arc::new(ArcSwap::from_pointee(HotState::new_with_config(
        Arc::new(routing),
        HashMap::new(),
        None,
        cors,
    )));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    let plugins = Arc::new(volta_gateway::plugin::PluginManager::new());
    ProxyService::new(volta, hot, metrics, plugins)
}

fn make_proxy_with_min_role(
    auth_addr: SocketAddr,
    backend_addr: SocketAddr,
    host: &str,
    min_role: &str,
) -> ProxyService {
    let proxy = make_proxy(auth_addr, backend_addr, host);
    let mut routing = (*proxy.hot.load_full().routing).clone();
    routing.get_mut(host).unwrap().min_role = Some(min_role.into());
    proxy.hot.store(Arc::new(HotState::new(Arc::new(routing))));
    proxy
}

// ─── Tests ──────────────────────────────────────────────

#[tokio::test]
async fn proxy_forwards_to_backend() {
    // Mock backend: return 200 with body
    let (backend_addr, _bh) = mock_server(|req| {
        assert_eq!(
            req.headers()
                .get("x-volta-assertion-key-id")
                .and_then(|value| value.to_str().ok()),
            Some("2026-08")
        );
        let timestamp = req
            .headers()
            .get("x-volta-assertion-timestamp")
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(timestamp.parse::<u64>().is_ok());
        let signature = req
            .headers()
            .get("x-volta-assertion-signature")
            .and_then(|value| value.to_str().ok())
            .unwrap();
        assert!(signature.starts_with("v1="));
        assert_ne!(signature, "v1=client-forgery");
        assert_eq!(req.headers().get("x-real-ip").unwrap(), "127.0.0.1");
        assert_eq!(req.headers().get("x-forwarded-for").unwrap(), "127.0.0.1");
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("x-custom", "preserved")
            .body(full_body(Bytes::from(r#"{"ok":true}"#)))
            .unwrap()
    })
    .await;

    // Mock volta auth: return 200 + X-Volta-User-Id
    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "test-user-123")
            .body(empty_body())
            .unwrap()
    })
    .await;

    let proxy = make_proxy(auth_addr, backend_addr, "app.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    // Client request
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .method("GET")
        .uri(format!("http://{}/api/test", proxy_addr))
        .header("host", "app.test.com")
        .header("x-volta-assertion-key-id", "attacker")
        .header("x-volta-assertion-timestamp", "1")
        .header("x-volta-assertion-signature", "v1=client-forgery")
        .header("x-real-ip", "10.0.0.7")
        .header("x-forwarded-for", "10.0.0.8")
        .body(Empty::<Bytes>::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // X-Volta-* should be stripped from response
    assert!(resp.headers().get("x-volta-user-id").is_none());
    // x-request-id should be present
    assert!(resp.headers().get("x-request-id").is_some());

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, r#"{"ok":true}"#);

    server.abort();
}

#[tokio::test]
async fn proxy_returns_403_on_auth_denied() {
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;

    // Mock volta auth: 403 denied
    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(403).body(empty_body()).unwrap()).await;

    let proxy = make_proxy(auth_addr, backend_addr, "app.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/api/test", proxy_addr))
        .header("host", "app.test.com")
        .body(Empty::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    server.abort();
}

#[tokio::test]
async fn auth_client_observes_revocation_on_the_next_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_for_server = calls.clone();
    let (auth_addr, _ah) = mock_server(move |_req| {
        if calls_for_server.fetch_add(1, Ordering::SeqCst) == 0 {
            Response::builder()
                .status(200)
                .header("x-volta-user-id", "user-1")
                .body(empty_body())
                .unwrap()
        } else {
            Response::builder().status(403).body(empty_body()).unwrap()
        }
    })
    .await;
    let config = AuthConfig {
        volta_url: format!("http://{auth_addr}"),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2_000,
        pool_max_idle: 4,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
    };
    let auth = VoltaAuthClient::new(&config);

    let first = auth
        .check(
            "app.test.com",
            "/account",
            "https",
            Some("session=same"),
            Some("app"),
            None,
            Some("192.0.2.1"),
            None,
        )
        .await;
    let second = auth
        .check(
            "app.test.com",
            "/account",
            "https",
            Some("session=same"),
            Some("app"),
            None,
            Some("192.0.2.1"),
            None,
        )
        .await;

    assert!(matches!(first, AuthResult::Authenticated(_)));
    assert!(matches!(second, AuthResult::Denied));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn proxy_enforces_min_role_hierarchy() {
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;
    let (auth_addr, _ah) = mock_server(|req| {
        let role = if req
            .headers()
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|cookie| cookie.contains("operator"))
        {
            "OPERATOR"
        } else {
            "MEMBER"
        };
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .header("x-volta-roles", role)
            .body(empty_body())
            .unwrap()
    })
    .await;
    let proxy = make_proxy_with_min_role(auth_addr, backend_addr, "roles.test.com", "OPERATOR");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            async move { Ok::<_, hyper::Error>(proxy.handle(req, remote_addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    for (cookie, expected) in [
        ("session=member", StatusCode::FORBIDDEN),
        ("session=operator", StatusCode::OK),
    ] {
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{proxy_addr}/admin"))
                    .header("host", "roles.test.com")
                    .header("cookie", cookie)
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let _ = response.into_body().collect().await.unwrap();
    }
    server.abort();
}

#[tokio::test]
async fn proxy_returns_502_on_backend_down() {
    // Bind a port then drop the listener — connection will be refused immediately
    let tmp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_backend_addr = tmp_listener.local_addr().unwrap();
    drop(tmp_listener); // port is now closed → connection refused

    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .body(empty_body())
            .unwrap()
    })
    .await;

    let proxy = make_proxy(auth_addr, dead_backend_addr, "app.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/api/test", proxy_addr))
        .header("host", "app.test.com")
        .body(Empty::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

    server.abort();
}

#[tokio::test]
async fn proxy_cors_preflight_returns_204() {
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;

    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;

    let proxy = make_proxy_with_cors(
        auth_addr,
        backend_addr,
        "app.test.com",
        vec!["https://app.test.com".into()],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .method("OPTIONS")
        .uri(format!("http://{}/api/test", proxy_addr))
        .header("host", "app.test.com")
        .header("origin", "https://app.test.com")
        .body(Empty::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://app.test.com"
    );
    assert!(resp.headers().get("access-control-max-age").is_some());

    server.abort();
}

#[tokio::test]
async fn proxy_rate_limit_returns_429() {
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;

    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .body(empty_body())
            .unwrap()
    })
    .await;

    let proxy = make_proxy(auth_addr, backend_addr, "app.test.com");

    // Send requests in a tight loop — should eventually hit rate limit
    // Default: 100 per-IP rps. We'll send 200 in quick succession.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let proxy = proxy_clone.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let proxy = proxy.clone();
                    let addr = remote_addr;
                    async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let mut got_429 = false;
    for _ in 0..200 {
        let req = Request::builder()
            .uri(format!("http://{}/api/test", proxy_addr))
            .header("host", "app.test.com")
            .body(Empty::new())
            .unwrap();

        let resp = client.request(req).await.unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "Expected 429 after exceeding rate limit");

    server.abort();
}

fn make_proxy_public(backend_addr: SocketAddr, host: &str) -> ProxyService {
    // Public route — auth is skipped, volta_url points to non-existent server
    let auth_config = AuthConfig {
        volta_url: "http://127.0.0.1:1".into(), // intentionally unreachable
        verify_path: "/auth/verify".into(),
        timeout_ms: 100,
        pool_max_idle: 1,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
        jwt_issuer: None,
        jwt_audience: None,
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        host.to_string(),
        volta_gateway::proxy::RouteInfo {
            min_role: None,
            weights: vec![],
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("public-app".into()),
            public: true,
            soft_auth: false,
            bypass_paths: vec![],
            auth_rules: vec![],
            mirror: None,
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            timeout_secs: None,
            cache: Some(volta_gateway::cache::CacheConfig {
                enabled: true,
                ttl_secs: 300,
                methods: vec!["GET".into()],
                max_body_size: 1_048_576,
                ignore_query: false,
            }),
            backend_tls: None,
        },
    );

    let hot = Arc::new(ArcSwap::from_pointee(HotState::new(Arc::new(routing))));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    let plugins = Arc::new(volta_gateway::plugin::PluginManager::new());
    ProxyService::new(volta, hot, metrics, plugins)
}

fn make_proxy_with_bypass(
    auth_addr: SocketAddr,
    backend_addr: SocketAddr,
    host: &str,
) -> ProxyService {
    let auth_config = AuthConfig {
        volta_url: format!("http://{}", auth_addr),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2000,
        pool_max_idle: 4,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
        jwt_issuer: None,
        jwt_audience: None,
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        host.to_string(),
        volta_gateway::proxy::RouteInfo {
            min_role: None,
            weights: vec![],
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("bypass-app".into()),
            public: false,
            soft_auth: false,
            bypass_paths: vec![volta_gateway::config::BypassPath {
                prefix: "/webhooks/".into(),
                backend: None,
            }],
            auth_rules: vec![],
            mirror: None,
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        },
    );

    let hot = Arc::new(ArcSwap::from_pointee(HotState::new(Arc::new(routing))));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    let plugins = Arc::new(volta_gateway::plugin::PluginManager::new());
    ProxyService::new(volta, hot, metrics, plugins)
}

#[tokio::test]
async fn proxy_public_route_skips_auth() {
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .body(full_body(Bytes::from(r#"{"public":true}"#)))
            .unwrap()
    })
    .await;

    // Auth is unreachable — but public route should skip it
    let proxy = make_proxy_public(backend_addr, "public.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let req = Request::builder()
        .uri(format!("http://{}/api/data", proxy_addr))
        .header("host", "public.test.com")
        .body(Empty::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, r#"{"public":true}"#);

    server.abort();
}

#[tokio::test]
async fn dynamic_public_route_with_min_role_fails_closed() {
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;
    let proxy = make_proxy_public(backend_addr, "bad-role.test.com");
    let mut routing = (*proxy.hot.load_full().routing).clone();
    routing.get_mut("bad-role.test.com").unwrap().min_role = Some("MEMBER".into());
    proxy.hot.store(Arc::new(HotState::new(Arc::new(routing))));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            async move { Ok::<_, hyper::Error>(proxy.handle(req, remote_addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{proxy_addr}/"))
                .header("host", "bad-role.test.com")
                .body(Empty::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    server.abort();
}

#[tokio::test]
async fn credentialed_public_requests_do_not_reuse_shared_cache() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend_calls = calls.clone();
    let (backend_addr, _bh) = mock_server(move |_req| {
        backend_calls.fetch_add(1, Ordering::SeqCst);
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(full_body(Bytes::from(r#"{"cached":true}"#)))
            .unwrap()
    })
    .await;
    let proxy = make_proxy_public(backend_addr, "public-cache.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            async move { Ok::<_, hyper::Error>(proxy.handle(req, remote_addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    for credential in [
        None,
        None,
        Some(("cookie", "session=private")),
        Some(("authorization", "Bearer private")),
    ] {
        let mut request = Request::builder()
            .uri(format!("http://{proxy_addr}/asset"))
            .header("host", "public-cache.test.com")
            .header("accept-encoding", "gzip");
        if let Some((name, value)) = credential {
            request = request.header(name, value);
        }
        let response = client
            .request(request.body(Empty::new()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.into_body().collect().await.unwrap();
    }

    // Request 2 is a shared-cache hit. Cookie and Authorization requests both
    // bypass lookup/store and therefore reach the backend independently.
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    server.abort();
}

#[tokio::test]
async fn public_cache_separates_query_strings() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend_calls = calls.clone();
    let (backend_addr, _bh) = mock_server(move |req| {
        backend_calls.fetch_add(1, Ordering::SeqCst);
        let query = req.uri().query().unwrap_or("none");
        Response::builder()
            .status(200)
            .header("content-type", "text/plain")
            .body(full_body(Bytes::from(query.to_owned())))
            .unwrap()
    })
    .await;
    let proxy = make_proxy_public(backend_addr, "query-cache.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            async move { Ok::<_, hyper::Error>(proxy.handle(req, remote_addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    let mut bodies = Vec::new();
    for path in ["/asset?q=secret", "/asset", "/asset?q=other"] {
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{proxy_addr}{path}"))
                    .header("host", "query-cache.test.com")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        bodies.push(response.into_body().collect().await.unwrap().to_bytes());
    }

    assert_eq!(
        bodies,
        [
            Bytes::from("q=secret"),
            Bytes::from("none"),
            Bytes::from("q=other"),
        ]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    server.abort();
}

#[tokio::test]
async fn proxy_unknown_host_returns_error() {
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;

    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;

    // Proxy is configured for "known.test.com" only
    let proxy = make_proxy(auth_addr, backend_addr, "known.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    // Request with unknown host
    let req = Request::builder()
        .uri(format!("http://{}/api/test", proxy_addr))
        .header("host", "unknown.test.com")
        .body(Empty::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    // Unknown host should return 400 or 502 (depends on SM error handling)
    assert!(resp.status().is_client_error() || resp.status().is_server_error());

    server.abort();
}

#[tokio::test]
async fn proxy_auth_bypass_path() {
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .body(full_body(Bytes::from(r#"{"webhook":"received"}"#)))
            .unwrap()
    })
    .await;

    // Auth denies everything — but bypass path should skip auth
    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(403).body(empty_body()).unwrap()).await;

    let proxy = make_proxy_with_bypass(auth_addr, backend_addr, "app.test.com");

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    // Request to bypass path — should reach backend despite auth denying
    let req = Request::builder()
        .uri(format!("http://{}/webhooks/stripe", proxy_addr))
        .header("host", "app.test.com")
        .body(Empty::new())
        .unwrap();

    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, r#"{"webhook":"received"}"#);

    server.abort();
}

/// #126: `min_role` + `auth_bypass_paths` 併用時の挙動。
/// bypass path (`/healthz`) に当たったリクエストは認証ごと skip し `min_role`
/// チェックも飛ばして下流へ流す（health 外形監視等）。
#[tokio::test]
async fn proxy_min_role_with_bypass_path_skips_auth_on_bypass() {
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .body(full_body(Bytes::from(r#"{"ok":true}"#)))
            .unwrap()
    })
    .await;

    // Auth denies everything (403) — bypass path だけは auth を呼ばない
    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(403).body(empty_body()).unwrap()).await;

    let auth_config = AuthConfig {
        volta_url: format!("http://{}", auth_addr),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2000,
        pool_max_idle: 4,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
        jwt_issuer: None,
        jwt_audience: None,
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        "health.test.com".to_string(),
        volta_gateway::proxy::RouteInfo {
            min_role: Some("MEMBER".into()),
            weights: vec![],
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("health-app".into()),
            public: false,
            soft_auth: false,
            bypass_paths: vec![volta_gateway::config::BypassPath {
                prefix: "/healthz".into(),
                backend: None,
            }],
            auth_rules: vec![],
            mirror: None,
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        },
    );

    let hot = Arc::new(ArcSwap::from_pointee(HotState::new(Arc::new(routing))));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    let plugins = Arc::new(volta_gateway::plugin::PluginManager::new());
    let proxy = ProxyService::new(volta, hot, metrics, plugins);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        let (stream, remote_addr) = listener.accept().await.unwrap();
        let service = service_fn(move |req: Request<Incoming>| {
            let proxy = proxy_clone.clone();
            let addr = remote_addr;
            async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
        });
        let _ = auto::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();

    // bypass path `/healthz` は auth を呼ばず 200 で下流へ届く
    let resp = client
        .request(
            Request::builder()
                .uri(format!("http://{}/healthz", proxy_addr))
                .header("host", "health.test.com")
                .body(Empty::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, r#"{"ok":true}"#);

    // 非 bypass path `/api/x` は auth が 403 を返すので 403
    let resp = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/x", proxy_addr))
                .header("host", "health.test.com")
                .body(Empty::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    server.abort();
}

// ─── #135: error responses must be counted in /metrics ───────────────
//
// Before #135, `record_status`/`record_duration` were called only on the
// success path. Every early-return error path (400/403/429/502/504) left
// `volta_gateway_requests_total` and the latency histogram untouched, so
// error-rate alerts and SLO latency could not see reality. These tests pin
// each error status to its counter so the regression cannot return.

/// Spin up a proxy listener and run a single request through it.
/// Returns the response status. The `proxy` handle is returned too so the
/// caller can inspect `proxy.metrics` (shared via the internal `Arc`).
async fn run_one_request(
    proxy: ProxyService,
    host: &str,
    path: &str,
) -> (StatusCode, ProxyService) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let proxy = proxy_clone.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let proxy = proxy.clone();
                    let addr = remote_addr;
                    async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    let resp = client
        .request(
            Request::builder()
                .uri(format!("http://{proxy_addr}{path}"))
                .header("host", host)
                .body(Empty::new())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    server.abort();
    (status, proxy)
}

#[tokio::test]
async fn metrics_count_403_on_auth_denied() {
    use std::sync::atomic::Ordering;
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;
    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(403).body(empty_body()).unwrap()).await;
    let proxy = make_proxy(auth_addr, backend_addr, "app.test.com");
    let before = proxy.metrics.requests_403.load(Ordering::Relaxed);
    let (status, proxy) = run_one_request(proxy, "app.test.com", "/api/x").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let after = proxy.metrics.requests_403.load(Ordering::Relaxed);
    assert_eq!(after - before, 1, "403 must be recorded in metrics");
}

#[tokio::test]
async fn metrics_count_400_on_unknown_host() {
    use std::sync::atomic::Ordering;
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;
    let (auth_addr, _ah) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;
    let proxy = make_proxy(auth_addr, backend_addr, "known.test.com");
    let before = proxy.metrics.requests_400.load(Ordering::Relaxed);
    let (status, proxy) = run_one_request(proxy, "unknown.test.com", "/api/x").await;
    // Unknown host → SM ends in BadRequest terminal → 400.
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let after = proxy.metrics.requests_400.load(Ordering::Relaxed);
    assert_eq!(after - before, 1, "400 must be recorded in metrics");
}

#[tokio::test]
async fn metrics_count_429_on_rate_limit() {
    use std::sync::atomic::Ordering;
    let (backend_addr, _bh) =
        mock_server(|_req| Response::builder().status(200).body(empty_body()).unwrap()).await;
    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .body(empty_body())
            .unwrap()
    })
    .await;
    let proxy = make_proxy(auth_addr, backend_addr, "app.test.com");
    let before = proxy.metrics.requests_429.load(Ordering::Relaxed);

    // Default limiter: 1000 global rps, 100 per-IP rps. Burst past per-IP.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy_clone = proxy.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let proxy = proxy_clone.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let proxy = proxy.clone();
                    let addr = remote_addr;
                    async move { Ok::<_, hyper::Error>(proxy.handle(req, addr).await) }
                });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let client: hyper_util::client::legacy::Client<_, Empty<Bytes>> =
        hyper_util::client::legacy::Client::builder(TokioExecutor::new()).build_http();
    let mut got_429 = false;
    for _ in 0..200 {
        let resp = client
            .request(
                Request::builder()
                    .uri(format!("http://{proxy_addr}/api/test"))
                    .header("host", "app.test.com")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(got_429, "should hit rate limit");
    let after = proxy.metrics.requests_429.load(Ordering::Relaxed);
    assert!(after - before >= 1, "429 must be recorded in metrics");
    server.abort();
}

#[tokio::test]
async fn metrics_count_502_on_backend_down() {
    use std::sync::atomic::Ordering;
    let tmp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_backend_addr = tmp_listener.local_addr().unwrap();
    drop(tmp_listener);
    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .body(empty_body())
            .unwrap()
    })
    .await;
    let proxy = make_proxy(auth_addr, dead_backend_addr, "app.test.com");
    let before = proxy.metrics.requests_502.load(Ordering::Relaxed);
    let (status, proxy) = run_one_request(proxy, "app.test.com", "/api/test").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let after = proxy.metrics.requests_502.load(Ordering::Relaxed);
    assert_eq!(after - before, 1, "502 must be recorded in metrics");
}

#[tokio::test]
async fn metrics_count_504_on_backend_timeout() {
    use std::sync::atomic::Ordering;
    // Backend accepts but never responds → gateway times out.
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend_listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match backend_listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            // Hold the connection open without responding until the gateway
            // times out. Keep reading so the kernel buffer doesn't fill and
            // RST the connection (which would surface as 502, not 504).
            let mut stream = stream;
            let mut buf = [0u8; 1024];
            loop {
                match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    });
    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .body(empty_body())
            .unwrap()
    })
    .await;

    // Build a proxy with a 1s per-route timeout so the test stays fast.
    let auth_config = AuthConfig {
        volta_url: format!("http://{}", auth_addr),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2000,
        pool_max_idle: 4,
        jwt_secret: None,
        cookie_name: None,
        auth_public_url: None,
        degraded_mode: false,
        jwt_public_key_pem: None,
        jwks_url: None,
        gateway_assertion_secret: None,
        gateway_assertion_key_id: None,
        gateway_assertion_previous_key_id: None,
        gateway_assertion_previous_secret: None,
        jwt_issuer: None,
        jwt_audience: None,
    };
    let volta = VoltaAuthClient::new(&auth_config);
    let mut routing = RoutingTable::new();
    routing.insert(
        "app.test.com".to_string(),
        volta_gateway::proxy::RouteInfo {
            min_role: None,
            weights: vec![],
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("test-app".into()),
            public: false,
            soft_auth: false,
            bypass_paths: vec![],
            auth_rules: vec![],
            mirror: None,
            path_prefix: None,
            strip_prefix: None,
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            timeout_secs: Some(1),
            cache: None,
            backend_tls: None,
        },
    );
    let hot = Arc::new(ArcSwap::from_pointee(HotState::new(Arc::new(routing))));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    let plugins = Arc::new(volta_gateway::plugin::PluginManager::new());
    let proxy = ProxyService::new(volta, hot, metrics, plugins);

    let before = proxy.metrics.requests_504.load(Ordering::Relaxed);
    let (status, proxy) = run_one_request(proxy, "app.test.com", "/api/test").await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    let after = proxy.metrics.requests_504.load(Ordering::Relaxed);
    assert_eq!(after - before, 1, "504 must be recorded in metrics");
}
