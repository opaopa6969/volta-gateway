use arc_swap::ArcSwap;
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
mod cache;
mod config_source;
mod l4_proxy;
mod middleware_ext;
mod metrics;
mod mtls;
mod plugin;
mod tls;
mod websocket;

use config::GatewayConfig;
use auth::VoltaAuthClient;
use proxy::{HotState, ProxyService};

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
    let ip_allowlists = config.ip_allowlist_table();
    let cors = config.cors_table();
    let trusted_proxies: Vec<ipnet::IpNet> = config.server.trusted_proxies.iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let hot = Arc::new(ArcSwap::from_pointee(
        HotState::new_full(routing, ip_allowlists, config.error_pages_dir.as_deref(), cors, trusted_proxies),
    ));
    let volta = VoltaAuthClient::new(&config.auth);
    let metrics = Arc::new(metrics::Metrics::new());
    let plugin_mgr = Arc::new(plugin::PluginManager::load_from_config(&config.plugins));
    let proxy = ProxyService::new(volta.clone(), hot.clone(), metrics.clone(), plugin_mgr);

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

    // GW-22: SIGHUP zero-downtime config reload via ArcSwap
    #[cfg(unix)]
    {
        let config_path_clone = config_path.clone();
        let hot_reload = hot.clone();
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
                            warn!("config reload aborted — keeping current config");
                        } else {
                            let new_routing = Arc::new(new_config.routing_table());
                            let new_allowlists = new_config.ip_allowlist_table();
                            let routes = new_config.routing.len();
                            let new_cors = new_config.cors_table();
                            let new_trusted: Vec<ipnet::IpNet> = new_config.server.trusted_proxies.iter()
                                .filter_map(|s| s.parse().ok()).collect();
                            hot_reload.store(Arc::new(
                                HotState::new_full(
                                    new_routing, new_allowlists,
                                    new_config.error_pages_dir.as_deref(),
                                    new_cors, new_trusted,
                                ),
                            ));
                            info!(routes = routes,
                                "config reloaded from {} — routing updated (zero-downtime)",
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

    // PROD-1: Backend health checker
    {
        let hot_snapshot = proxy.hot.load();
        proxy::spawn_health_checker(
            hot_snapshot.routing.clone(),
            proxy.backend_selector.clone(),
            config.healthcheck.interval_secs,
            config.healthcheck.path.clone(),
        );
    }

    // Start HTTPS/ACME listener if TLS config is present
    if let Some(ref tls_config) = config.tls {
        let tls_proxy = proxy.clone();
        let tls_volta = volta.clone();
        let tls_metrics = metrics.clone();
        let tls_in_flight = in_flight.clone();
        let tls_config = tls_config.clone();
        tokio::spawn(async move {
            tls::serve_tls(&tls_config, tls_proxy, tls_volta, tls_metrics, tls_in_flight).await;
        });
    }

    // Start L4 (TCP/UDP) proxy listeners
    if !config.l4_proxy.is_empty() {
        info!(count = config.l4_proxy.len(), "starting L4 proxy listeners");
        l4_proxy::spawn_l4_proxies(&config.l4_proxy);
    }

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
        let force_https = config.server.force_https && config.tls.is_some();
        let tls_port = config.tls.as_ref().map(|t| t.port).unwrap_or(443);
        let hot_admin = hot.clone();
        let config_path_admin = config_path.clone();
        let shutdown_admin = shutdown.clone();
        let error_pages_dir_admin = config.error_pages_dir.clone();

        in_flight.fetch_add(1, Ordering::SeqCst);
        metrics.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            let metrics2 = metrics.clone();
            let hot_admin2 = hot_admin.clone();
            let config_path_admin2 = config_path_admin.clone();
            let error_pages_dir_admin2 = error_pages_dir_admin.clone();
            let shutdown_admin2 = shutdown_admin.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy = proxy.clone();
                let volta_health = volta_health.clone();
                let metrics = metrics2.clone();
                let hot_admin = hot_admin2.clone();
                let config_path_admin = config_path_admin2.clone();
                let error_pages_dir_admin = error_pages_dir_admin2.clone();
                let shutdown_admin = shutdown_admin2.clone();
                let addr = remote_addr;
                async move {
                    // HTTP → HTTPS redirect (GW-29/GW-38: skip for healthz, metrics, ACME challenge)
                    if force_https {
                        let path = req.uri().path();
                        let skip_redirect = path == "/healthz"
                            || path == "/metrics"
                            || path.starts_with("/.well-known/");
                        if !skip_redirect {
                            let host = req.headers().get("host")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("localhost");
                            // IPv6-aware host parsing
                            let host_no_port = if host.starts_with('[') {
                                host.split(']').next()
                                    .map(|s| format!("{}]", s))
                                    .unwrap_or_else(|| host.to_string())
                            } else {
                                host.split(':').next().unwrap_or(host).to_string()
                            };
                            let pq = req.uri().path_and_query()
                                .map(|pq| pq.as_str())
                                .unwrap_or("/");
                            let location = if tls_port == 443 {
                                format!("https://{}{}", host_no_port, pq)
                            } else {
                                format!("https://{}:{}{}", host_no_port, tls_port, pq)
                            };
                            let resp = hyper::Response::builder()
                                .status(301)
                                .header("location", location)
                                .body(Full::new(Bytes::from("Moved Permanently")).map_err(|e| match e {}).boxed())
                                .unwrap();
                            return Ok::<_, hyper::Error>(resp);
                        }
                    }

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

                    // PROD-2/3: Admin API (localhost only)
                    if req.uri().path().starts_with("/admin/") {
                        if !addr.ip().is_loopback() {
                            let resp = hyper::Response::builder()
                                .status(403)
                                .body(Full::new(Bytes::from(r#"{"error":"admin API is localhost only"}"#)).map_err(|e| match e {}).boxed())
                                .unwrap();
                            return Ok::<_, hyper::Error>(resp);
                        }

                        match req.uri().path() {
                            "/admin/routes" => {
                                let hot = hot_admin.load();
                                let routes: Vec<serde_json::Value> = hot.routing.iter()
                                    .map(|(host, info)| serde_json::json!({
                                        "host": host,
                                        "backends": info.backends,
                                        "app_id": info.app_id,
                                        "public": info.public,
                                    })).collect();
                                let body = serde_json::to_string(&routes).unwrap_or_else(|_| "[]".into());
                                let resp = hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                                    .unwrap();
                                return Ok(resp);
                            }
                            "/admin/backends" => {
                                let health = proxy.backend_selector.health_status();
                                let entries: Vec<serde_json::Value> = health.iter()
                                    .map(|(url, alive)| serde_json::json!({"url": url, "alive": alive}))
                                    .collect();
                                let body = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into());
                                let resp = hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                                    .unwrap();
                                return Ok(resp);
                            }
                            "/admin/reload" if req.method() == hyper::Method::POST => {
                                match GatewayConfig::load(std::path::Path::new(&config_path_admin)) {
                                    Ok(new_config) => {
                                        if let Err(errors) = new_config.validate() {
                                            let body = format!(r#"{{"error":"validation failed","details":{:?}}}"#, errors);
                                            let resp = hyper::Response::builder()
                                                .status(400)
                                                .header("content-type", "application/json")
                                                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                                                .unwrap();
                                            return Ok(resp);
                                        }
                                        let new_routing = Arc::new(new_config.routing_table());
                                        let new_allowlists = new_config.ip_allowlist_table();
                                        let new_cors = new_config.cors_table();
                                        let routes = new_config.routing.len();
                                        hot_admin.store(Arc::new(HotState::new_with_config(
                                            new_routing, new_allowlists,
                                            error_pages_dir_admin.as_deref(), new_cors,
                                        )));
                                        info!(routes = routes, "config reloaded via admin API");
                                        let resp = hyper::Response::builder()
                                            .status(200)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from(format!(r#"{{"status":"reloaded","routes":{}}}"#, routes))).map_err(|e| match e {}).boxed())
                                            .unwrap();
                                        return Ok(resp);
                                    }
                                    Err(e) => {
                                        let resp = hyper::Response::builder()
                                            .status(500)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from(format!(r#"{{"error":"{}"}}"#, e))).map_err(|e| match e {}).boxed())
                                            .unwrap();
                                        return Ok(resp);
                                    }
                                }
                            }
                            "/admin/drain" if req.method() == hyper::Method::POST => {
                                info!("drain requested via admin API");
                                shutdown_admin.store(true, Ordering::SeqCst);
                                let resp = hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(r#"{"status":"draining"}"#)).map_err(|e| match e {}).boxed())
                                    .unwrap();
                                return Ok(resp);
                            }
                            _ => {
                                let resp = hyper::Response::builder()
                                    .status(404)
                                    .body(Full::new(Bytes::from(r#"{"error":"unknown admin endpoint"}"#)).map_err(|e| match e {}).boxed())
                                    .unwrap();
                                return Ok(resp);
                            }
                        }
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
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
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
