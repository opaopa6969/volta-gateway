//! Integration tests: real HTTP requests through volta-gateway proxy.
//!
//! Each test spins up:
//!   - Mock backend (echo server)
//!   - Mock volta-auth-proxy
//!   - volta-gateway ProxyService
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
use std::sync::Arc;
use tokio::net::TcpListener;

use volta_gateway::auth::VoltaAuthClient;
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
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        host.to_string(),
        volta_gateway::proxy::RouteInfo {
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("test-app".into()),
            public: false,
            bypass_paths: vec![], mirror: None,
            path_prefix: None, strip_prefix: None, add_prefix: None,
            request_headers: None, response_headers: None,
            geo_allowlist: vec![], geo_denylist: vec![],
        },
    );

    let hot = Arc::new(ArcSwap::from_pointee(HotState::new(Arc::new(routing))));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    ProxyService::new(volta, hot, metrics)
}

fn make_proxy_with_cors(auth_addr: SocketAddr, backend_addr: SocketAddr, host: &str, origins: Vec<String>) -> ProxyService {
    let auth_config = AuthConfig {
        volta_url: format!("http://{}", auth_addr),
        verify_path: "/auth/verify".into(),
        timeout_ms: 2000,
        pool_max_idle: 4,
    };
    let volta = VoltaAuthClient::new(&auth_config);

    let mut routing = RoutingTable::new();
    routing.insert(
        host.to_string(),
        volta_gateway::proxy::RouteInfo {
            backends: vec![format!("http://{}", backend_addr)],
            app_id: Some("test-app".into()),
            public: false,
            bypass_paths: vec![], mirror: None,
            path_prefix: None, strip_prefix: None, add_prefix: None,
            request_headers: None, response_headers: None,
            geo_allowlist: vec![], geo_denylist: vec![],
        },
    );

    let mut cors = HashMap::new();
    cors.insert(host.to_string(), origins);

    let hot = Arc::new(ArcSwap::from_pointee(
        HotState::new_with_config(Arc::new(routing), HashMap::new(), None, cors),
    ));
    let metrics = Arc::new(volta_gateway::metrics::Metrics::new());
    ProxyService::new(volta, hot, metrics)
}

// ─── Tests ──────────────────────────────────────────────

#[tokio::test]
async fn proxy_forwards_to_backend() {
    // Mock backend: return 200 with body
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .header("x-custom", "preserved")
            .body(full_body(Bytes::from(r#"{"ok":true}"#)))
            .unwrap()
    }).await;

    // Mock volta auth: return 200 + X-Volta-User-Id
    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "test-user-123")
            .body(empty_body())
            .unwrap()
    }).await;

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
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder().status(200).body(empty_body()).unwrap()
    }).await;

    // Mock volta auth: 403 denied
    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder().status(403).body(empty_body()).unwrap()
    }).await;

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
    }).await;

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
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder().status(200).body(empty_body()).unwrap()
    }).await;

    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder().status(200).body(empty_body()).unwrap()
    }).await;

    let proxy = make_proxy_with_cors(
        auth_addr, backend_addr, "app.test.com",
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
    let (backend_addr, _bh) = mock_server(|_req| {
        Response::builder().status(200).body(empty_body()).unwrap()
    }).await;

    let (auth_addr, _ah) = mock_server(|_req| {
        Response::builder()
            .status(200)
            .header("x-volta-user-id", "user")
            .body(empty_body())
            .unwrap()
    }).await;

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
