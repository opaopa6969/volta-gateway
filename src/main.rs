use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::server::conn::auto;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
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
mod metrics;

use config::GatewayConfig;
use auth::VoltaAuthClient;
use proxy::ProxyService;

#[tokio::main]
async fn main() {
    // GW-24: VOLTA_LOG_FORMAT=pretty for human-readable logs (default: json)
    let log_format = std::env::var("VOLTA_LOG_FORMAT").unwrap_or_else(|_| "json".into());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "volta_gateway=info".into());
    if log_format == "pretty" {
        tracing_subscriber::fmt().with_env_filter(filter).pretty().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    }

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "volta-gateway.yaml".into());

    let config = GatewayConfig::load(Path::new(&config_path))
        .unwrap_or_else(|e| {
            error!("Failed to load config {}: {}", config_path, e);
            std::process::exit(1);
        });

    // PH2-4: Config validation
    if let Err(errors) = config.validate() {
        for e in &errors { error!("config error: {e}"); }
        error!("config validation failed ({} errors) — exiting", errors.len());
        std::process::exit(1);
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], config.server.port));
    let routing = Arc::new(config.routing_table());
    let volta = VoltaAuthClient::new(&config.auth);
    let proxy = ProxyService::new(volta.clone(), routing);
    let metrics = Arc::new(metrics::Metrics::new());

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

    // GW-22: SIGHUP config reload notification
    #[cfg(unix)]
    {
        let config_path_clone = config_path.clone();
        tokio::spawn(async move {
            let mut sighup = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup()
            ).expect("failed to register SIGHUP");
            loop {
                sighup.recv().await;
                match GatewayConfig::load(std::path::Path::new(&config_path_clone)) {
                    Ok(new_config) => {
                        if let Err(errors) = new_config.validate() {
                            for e in &errors { warn!("reload config error: {e}"); }
                        } else {
                            info!(routes = new_config.routing.len(),
                                "config reloaded from {}. Restart to apply routing changes.",
                                config_path_clone);
                        }
                    }
                    Err(e) => warn!("failed to reload config: {e}"),
                }
            }
        });
    }

    // PH2-2: Rate limiter GC task (cleanup idle IP entries every 30s)
    let rl = proxy.rate_limiter.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            rl.gc(std::time::Duration::from_secs(60));
        }
    });

    // Track in-flight connections
    let in_flight = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let mut drain_deadline: Option<tokio::time::Instant> = None;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            // GW-15: drain with 30s timeout
            let deadline = *drain_deadline.get_or_insert(
                tokio::time::Instant::now() + std::time::Duration::from_secs(30));
            let remaining = in_flight.load(Ordering::SeqCst);
            if remaining == 0 {
                info!("all connections drained — shutting down");
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(remaining = remaining, "drain timeout (30s) — forcing shutdown");
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
        let metrics = metrics.clone();

        in_flight.fetch_add(1, Ordering::SeqCst);
        metrics.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            let metrics2 = metrics.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy = proxy.clone();
                let volta_health = volta_health.clone();
                let metrics = metrics2.clone();
                let addr = remote_addr;
                async move {
                    // PH2-3: /metrics endpoint
                    if req.uri().path() == "/metrics" {
                        let body = metrics.render();
                        let resp = hyper::Response::builder()
                            .status(200)
                            .header("content-type", "text/plain; version=0.0.4")
                            .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                            .unwrap();
                        return Ok::<_, hyper::Error>(resp);
                    }

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

            // PH2-1: HTTP/1.1 + HTTP/2 auto-negotiation
            // PH2-7: chunked body limit 10MB
            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .http1()
                .max_buf_size(10 * 1024 * 1024)
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection(TokioIo::new(stream), service)
                .await
            {
                // auto::Builder returns Box<dyn Error> — just log it
                let msg = e.to_string();
                if !msg.contains("connection closed") && !msg.contains("incomplete") {
                    error!(remote = %remote_addr, "connection error: {msg}");
                }
            }

            in_flight.fetch_sub(1, Ordering::SeqCst);
            metrics.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
