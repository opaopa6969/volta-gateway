//! Mock volta-auth-proxy for E2E benchmarks.
//! Usage: cargo run --release --example mock_auth

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let port = std::env::args().nth(1).unwrap_or("7070".into()).parse::<u16>().unwrap();
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();
    eprintln!("mock auth listening on 127.0.0.1:{}", port);

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let service = service_fn(|req: Request<Incoming>| async move {
                if req.uri().path() == "/healthz" {
                    return Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .body(Full::new(Bytes::from(r#"{"status":"ok"}"#)))
                            .unwrap()
                    );
                }
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(200)
                        .header("x-volta-user-id", "bench-user-001")
                        .header("x-volta-email", "bench@example.com")
                        .header("x-volta-tenant-id", "tenant-001")
                        .body(Full::new(Bytes::new()))
                        .unwrap()
                )
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
