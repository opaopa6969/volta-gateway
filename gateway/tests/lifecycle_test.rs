//! Integration test for the server-lifecycle decisions factored out of
//! `main.rs` (Phase 3 notDone回収).
//!
//! We stand up a *minimal* hyper server on an ephemeral port that wires the
//! same `lifecycle::*` and `admin_auth::*` helpers the real binary uses for
//! `/healthz`, `/admin/*` and the drain flag, then drive it with real TCP
//! requests to assert the 200/503/401/200 behaviour and the post-drain change.
//!
//! This exercises the helpers end-to-end through actual HTTP without needing
//! the full proxy / config / TLS machinery.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::{TcpListener, TcpStream};

use volta_gateway::{admin_auth, lifecycle};

type Body = BoxBody<Bytes, hyper::Error>;

/// Shared server knobs the test can flip at runtime.
struct Ctx {
    shutdown: AtomicBool,
    admin_token: Option<String>,
}

/// A tiny replica of the relevant branches of the real connection service,
/// built only from the factored-out lifecycle/admin helpers.
async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: Arc<Ctx>,
) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path();

    if path == "/healthz" {
        let draining = ctx.shutdown.load(Ordering::SeqCst);
        // In the real server a degraded auth probe also yields 503; here the
        // upstream is always "ok" so we only test the drain transition.
        let volta_ok = !draining;
        let status = lifecycle::healthz_status(draining, volta_ok);
        return Ok(lifecycle::healthz_response(status));
    }

    if path.starts_with("/admin/") {
        if !lifecycle::admin_loopback_allowed(peer.ip().is_loopback()) {
            return Ok(lifecycle::admin_loopback_denied_response());
        }
        let is_mutating = req.method() != hyper::Method::GET;
        let auth_header = req
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        match admin_auth::decide(ctx.admin_token.as_deref(), auth_header, is_mutating) {
            admin_auth::AdminAuth::Allow => {}
            admin_auth::AdminAuth::Unauthorized => {
                return Ok(Response::builder()
                    .status(401)
                    .body(Full::new(Bytes::from(r#"{"error":"unauthorized"}"#)).map_err(|e| match e {}).boxed())
                    .unwrap());
            }
            admin_auth::AdminAuth::WriteDisabled => {
                return Ok(Response::builder()
                    .status(403)
                    .body(Full::new(Bytes::from(r#"{"error":"write disabled"}"#)).map_err(|e| match e {}).boxed())
                    .unwrap());
            }
        }
        if path == "/admin/drain" && req.method() == hyper::Method::POST {
            ctx.shutdown.store(true, Ordering::SeqCst);
        }
        return Ok(Response::builder()
            .status(200)
            .body(Full::new(Bytes::from(r#"{"status":"ok"}"#)).map_err(|e| match e {}).boxed())
            .unwrap());
    }

    Ok(Response::builder()
        .status(404)
        .body(Full::new(Bytes::from("not found")).map_err(|e| match e {}).boxed())
        .unwrap())
}

/// Bind to an ephemeral loopback port and serve `handle` until the test drops.
/// Returns the bound address so the test can connect.
async fn spawn_server(ctx: Arc<Ctx>) -> SocketAddr {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req| handle(req, peer, ctx.clone()));
                let _ = auto::Builder::new(TokioExecutor::new())
                    .http1()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    addr
}

/// Send a raw HTTP/1.1 request over a fresh TCP connection and return
/// `(status_line, full_response_text)`.
async fn raw_request(addr: SocketAddr, method: &str, path: &str, extra_headers: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n{extra_headers}\r\n"
    );
    stream.write_all(req.as_bytes()).await.expect("write");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.expect("read");
    let text = String::from_utf8_lossy(&buf).into_owned();

    // Parse "HTTP/1.1 <code> <reason>" from the status line.
    let code = text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    (code, text)
}

#[tokio::test]
async fn healthz_200_then_503_after_drain() {
    let token = "test-admin-token";
    let ctx = Arc::new(Ctx {
        shutdown: AtomicBool::new(false),
        admin_token: Some(token.to_string()),
    });
    let addr = spawn_server(ctx.clone()).await;

    // Before drain: 200 ok.
    let (code, body) = raw_request(addr, "GET", "/healthz", "").await;
    assert_eq!(code, 200, "healthz should be 200 before drain: {body}");
    assert!(body.contains(r#""status":"ok""#), "body: {body}");

    // Admin drain without a token → 401.
    let (code, _) = raw_request(addr, "POST", "/admin/drain", "").await;
    assert_eq!(code, 401, "drain without bearer token must be 401");

    // Health is still ok — the failed (401) drain didn't flip the flag.
    let (code, _) = raw_request(addr, "GET", "/healthz", "").await;
    assert_eq!(code, 200, "healthz must stay 200 after a rejected drain");

    // Admin drain with the correct token → 200, flips the drain flag.
    let auth = format!("Authorization: Bearer {token}\r\n");
    let (code, _) = raw_request(addr, "POST", "/admin/drain", &auth).await;
    assert_eq!(code, 200, "authorized drain must be 200");

    // After drain: healthz reports 503 (draining).
    let (code, body) = raw_request(addr, "GET", "/healthz", "").await;
    assert_eq!(code, 503, "healthz must be 503 after drain: {body}");
    assert!(body.contains(r#""status":"draining""#), "body: {body}");
}

#[tokio::test]
async fn admin_401_then_200_with_token() {
    let token = "s3cr3t";
    let ctx = Arc::new(Ctx {
        shutdown: AtomicBool::new(false),
        admin_token: Some(token.to_string()),
    });
    let addr = spawn_server(ctx).await;

    // No / wrong token → 401.
    let (code, _) = raw_request(addr, "GET", "/admin/routes", "").await;
    assert_eq!(code, 401, "GET /admin/* without token must be 401");

    let (code, _) = raw_request(
        addr,
        "GET",
        "/admin/routes",
        "Authorization: Bearer wrong\r\n",
    )
    .await;
    assert_eq!(code, 401, "GET /admin/* with wrong token must be 401");

    // Correct token → 200.
    let auth = format!("Authorization: Bearer {token}\r\n");
    let (code, _) = raw_request(addr, "GET", "/admin/routes", &auth).await;
    assert_eq!(code, 200, "GET /admin/* with correct token must be 200");
}
