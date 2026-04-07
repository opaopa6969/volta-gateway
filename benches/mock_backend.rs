//! Mock backend for E2E benchmarks.
//! Usage: cargo run --release --example mock_backend

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
    let port = std::env::args().nth(1).unwrap_or("9001".into()).parse::<u16>().unwrap();
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await.unwrap();
    eprintln!("mock backend listening on 127.0.0.1:{}", port);

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let service = service_fn(|_req: Request<Incoming>| async {
                let body = r#"{"status":"ok","service":"mock-backend"}"#;
                Ok::<_, hyper::Error>(
                    Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap()
                )
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
