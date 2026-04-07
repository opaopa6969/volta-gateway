use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

mod config;
mod state;
mod auth;
mod proxy;
mod flow;

use config::GatewayConfig;
use auth::VoltaAuthClient;
use proxy::ProxyService;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "volta_gateway=info".into()),
        )
        .json()
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "volta-gateway.yaml".into());

    let config = GatewayConfig::load(Path::new(&config_path))
        .unwrap_or_else(|e| {
            error!("Failed to load config {}: {}", config_path, e);
            std::process::exit(1);
        });

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    let routing = Arc::new(config.routing_table());
    let volta = VoltaAuthClient::new(&config.auth);
    let proxy = ProxyService::new(volta.clone(), routing);

    info!(port = config.server.port, "volta-gateway starting");

    let listener = TcpListener::bind(addr).await.unwrap();
    info!(addr = %addr, "listening");

    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("accept error: {e}");
                continue;
            }
        };

        let proxy = proxy.clone();
        let volta_health = volta.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy = proxy.clone();
                let volta_health = volta_health.clone();
                async move {
                    if req.uri().path() == "/healthz" {
                        let volta_ok = volta_health.health().await;
                        let body = format!(
                            r#"{{"status":"{}","volta":"{}"}}"#,
                            if volta_ok { "ok" } else { "degraded" },
                            if volta_ok { "ok" } else { "down" },
                        );
                        let resp = hyper::Response::builder()
                            .status(if volta_ok { 200 } else { 503 })
                            .header("content-type", "application/json")
                            .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                            .unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }

                    Ok(proxy.handle(req).await)
                }
            });

            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                if !e.is_incomplete_message() {
                    error!(remote = %remote_addr, "connection error: {e}");
                }
            }
        });
    }
}
