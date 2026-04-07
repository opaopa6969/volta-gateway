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
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

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

    // ─── GW-5: Graceful shutdown ────────────────────────
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_flag = shutdown.clone();

    // Spawn shutdown signal listener
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("shutdown signal received — draining connections...");
        shutdown_flag.store(true, Ordering::SeqCst);
    });

    // Track in-flight connections
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    loop {
        if shutdown.load(Ordering::SeqCst) {
            // Stop accepting new connections
            let remaining = in_flight.load(Ordering::SeqCst);
            if remaining == 0 {
                info!("all connections drained — shutting down");
                break;
            }
            info!(remaining = remaining, "waiting for in-flight connections...");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            continue;
        }

        let accept = tokio::time::timeout(
            std::time::Duration::from_millis(250),
            listener.accept(),
        ).await;

        let (stream, remote_addr) = match accept {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                error!("accept error: {e}");
                continue;
            }
            Err(_) => continue, // timeout — check shutdown flag
        };

        let proxy = proxy.clone();
        let volta_health = volta.clone();
        let in_flight = in_flight.clone();

        in_flight.fetch_add(1, Ordering::SeqCst);

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy = proxy.clone();
                let volta_health = volta_health.clone();
                let addr = remote_addr;
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

                    Ok(proxy.handle(req, addr).await)
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

            in_flight.fetch_sub(1, Ordering::SeqCst);
        });
    }
}
