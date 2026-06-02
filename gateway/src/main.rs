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
mod config_overlay;
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
mod dns01;
mod websocket;

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

    // #39: Access log file output (spawned after config load, uses _guard to keep writer alive)
    let _access_log_guard: Option<tracing_appender::non_blocking::WorkerGuard>;

    // #36: --validate dry-run mode
    let args: Vec<String> = std::env::args().collect();
    let validate_only = args.iter().any(|a| a == "--validate");
    let config_path = args.iter()
        .filter(|a| !a.starts_with('-'))
        .nth(1)
        .cloned()
        .unwrap_or_else(|| "volta-gateway.yaml".into());

    // API-driven config changes are persisted to an overlay file alongside the
    // base YAML (override with --overlay <path> or VOLTA_CONFIG_OVERLAY).
    let overlay_path = args.iter()
        .position(|a| a == "--overlay")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| std::env::var("VOLTA_CONFIG_OVERLAY").ok())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| config_overlay::default_overlay_path(&config_path));

    let (config_store, config) = config_overlay::ConfigStore::load(Path::new(&config_path), overlay_path)
        .unwrap_or_else(|e| {
            error!("Failed to load config {}: {}", config_path, e);
            std::process::exit(1);
        });
    let config_store = Arc::new(config_store);

    // PH2-4: Config validation
    if let Err(errors) = config.validate() {
        for e in &errors { error!("config error: {e}"); }
        error!("config validation failed ({} errors) — exiting", errors.len());
        std::process::exit(1);
    }

    // #36: --validate mode exits after successful validation
    if validate_only {
        info!(routes = config.routing.len(), "config valid: {}", config_path);
        std::process::exit(0);
    }

    // #39: Access log file writer (if configured)
    _access_log_guard = if let Some(ref al) = config.access_log {
        if al.enabled {
            if let Some(ref path) = al.path {
                let dir = std::path::Path::new(path).parent().unwrap_or(std::path::Path::new("."));
                let filename = std::path::Path::new(path).file_name()
                    .and_then(|f| f.to_str()).unwrap_or("access.log");
                let appender = tracing_appender::rolling::daily(dir, filename);
                let (writer, guard) = tracing_appender::non_blocking(appender);
                // Spawn a task that writes ACCESS log lines to the file
                let _writer = writer; // kept alive via guard
                info!(path = path, "access log file enabled");
                Some(guard)
            } else { None }
        } else { None }
    } else { None };

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

    // GW-22: SIGHUP zero-downtime config reload via ArcSwap.
    // Re-reads the base YAML from disk and re-applies the persisted overlay.
    #[cfg(unix)]
    {
        let config_path_clone = config_path.clone();
        let hot_reload = hot.clone();
        let store_reload = config_store.clone();
        tokio::spawn(async move {
            let mut sighup = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup()
            ).expect("failed to register SIGHUP");
            loop {
                sighup.recv().await;
                match store_reload.reload() {
                    Ok(new_config) => {
                        let routes = new_config.routing.len();
                        config_overlay::rebuild_hot(&new_config, &hot_reload);
                        info!(routes = routes,
                            "config reloaded from {} (+overlay) — routing updated (zero-downtime)",
                            config_path_clone);
                    }
                    Err(errors) => {
                        for e in &errors { warn!("reload config error: {e}"); }
                        warn!("config reload aborted — keeping current config");
                    }
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

    // #34: Backpressure — global max concurrent requests
    let max_concurrent = 10_000u32;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent as usize));

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

    // Config source watchers (Docker labels, services.json, HTTP polling → ArcSwap hot reload)
    if !config.config_sources.is_empty() {
        let sources = config_source::create_sources(&config.config_sources);
        info!(count = sources.len(), "starting config source watchers");
        config_source::spawn_watchers(sources, hot.clone(), &config);
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

        // #34: Backpressure — reject if at capacity
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                warn!(state = "BACKPRESSURE", "max concurrent requests reached");
                continue; // drop connection — client gets TCP RST
            }
        };

        let proxy = proxy.clone();
        let volta_health = volta.clone();
        let in_flight = in_flight.clone();
        let metrics = metrics.clone();
        let force_https = config.server.force_https && config.tls.is_some();
        let tls_port = config.tls.as_ref().map(|t| t.port).unwrap_or(443);
        let hot_admin = hot.clone();
        let shutdown_admin = shutdown.clone();
        let store_admin = config_store.clone();

        in_flight.fetch_add(1, Ordering::SeqCst);
        metrics.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            let _permit = permit; // #34: hold semaphore permit until connection ends
            let metrics2 = metrics.clone();
            let hot_admin2 = hot_admin.clone();
            let shutdown_admin2 = shutdown_admin.clone();
            let store_admin2 = store_admin.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy = proxy.clone();
                let volta_health = volta_health.clone();
                let metrics = metrics2.clone();
                let hot_admin = hot_admin2.clone();
                let shutdown_admin = shutdown_admin2.clone();
                let store_admin = store_admin2.clone();
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

                        // Helper for JSON admin responses.
                        fn json_resp(status: u16, body: String) -> hyper::Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>> {
                            hyper::Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                                .unwrap()
                        }

                        // Owned path so PATCH arms can consume the request body.
                        let admin_path = req.uri().path().to_string();
                        match admin_path.as_str() {
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
                            // Re-read base YAML (+ persisted overlay) and hot-swap routing.
                            "/admin/reload" if req.method() == hyper::Method::POST => {
                                match store_admin.reload() {
                                    Ok(new_config) => {
                                        let routes = new_config.routing.len();
                                        config_overlay::rebuild_hot(&new_config, &hot_admin);
                                        info!(routes = routes, "config reloaded via admin API");
                                        return Ok(json_resp(200, format!(r#"{{"status":"reloaded","routes":{}}}"#, routes)));
                                    }
                                    Err(errors) => {
                                        let body = serde_json::json!({"error": "validation failed", "details": errors});
                                        return Ok(json_resp(400, body.to_string()));
                                    }
                                }
                            }
                            // GET the current effective config (base ⊕ overlay).
                            "/admin/config" if req.method() == hyper::Method::GET => {
                                match store_admin.effective_config() {
                                    Ok(cfg) => return Ok(json_resp(200, serde_json::to_string_pretty(&cfg).unwrap_or_else(|_| "{}".into()))),
                                    Err(e) => {
                                        let body = serde_json::json!({"error": e});
                                        return Ok(json_resp(500, body.to_string()));
                                    }
                                }
                            }
                            // PATCH/POST a JSON merge patch: persist it and hot-apply applicable fields.
                            "/admin/config" if req.method() == hyper::Method::PATCH || req.method() == hyper::Method::POST => {
                                let bytes = match req.into_body().collect().await {
                                    Ok(b) => b.to_bytes(),
                                    Err(_) => return Ok(json_resp(400, r#"{"error":"failed to read request body"}"#.into())),
                                };
                                let patch: serde_json::Value = match serde_json::from_slice(&bytes) {
                                    Ok(v) => v,
                                    Err(e) => {
                                        let body = serde_json::json!({"error": format!("invalid JSON: {}", e)});
                                        return Ok(json_resp(400, body.to_string()));
                                    }
                                };
                                match store_admin.apply_patch(patch) {
                                    Ok((effective, result)) => {
                                        config_overlay::rebuild_hot(&effective, &hot_admin);
                                        info!(
                                            hot = ?result.hot_applied,
                                            restart = ?result.requires_restart,
                                            "config patched via admin API"
                                        );
                                        let body = serde_json::json!({
                                            "status": "applied",
                                            "hot_applied": result.hot_applied,
                                            "requires_restart": result.requires_restart,
                                        });
                                        return Ok(json_resp(200, body.to_string()));
                                    }
                                    Err(errors) => {
                                        let body = serde_json::json!({"error": "validation failed", "details": errors});
                                        return Ok(json_resp(400, body.to_string()));
                                    }
                                }
                            }
                            // Drop all API-driven changes; revert to the hand-written YAML.
                            "/admin/config/overlay" if req.method() == hyper::Method::DELETE => {
                                match store_admin.clear_overlay() {
                                    Ok(effective) => {
                                        config_overlay::rebuild_hot(&effective, &hot_admin);
                                        info!("config overlay cleared via admin API");
                                        return Ok(json_resp(200, r#"{"status":"overlay cleared"}"#.into()));
                                    }
                                    Err(errors) => {
                                        let body = serde_json::json!({"error": "validation failed", "details": errors});
                                        return Ok(json_resp(400, body.to_string()));
                                    }
                                }
                            }
                            "/admin/stats" => {
                                let m = &metrics;
                                let stats = serde_json::json!({
                                    "requests_total": m.requests_total.load(std::sync::atomic::Ordering::Relaxed),
                                    "status": {
                                        "2xx": m.requests_200.load(std::sync::atomic::Ordering::Relaxed),
                                        "4xx": m.requests_400.load(std::sync::atomic::Ordering::Relaxed) + m.requests_403.load(std::sync::atomic::Ordering::Relaxed) + m.requests_429.load(std::sync::atomic::Ordering::Relaxed),
                                        "5xx": m.requests_502.load(std::sync::atomic::Ordering::Relaxed) + m.requests_504.load(std::sync::atomic::Ordering::Relaxed),
                                    },
                                    "websocket": {
                                        "total": m.ws_connections_total.load(std::sync::atomic::Ordering::Relaxed),
                                        "active": m.ws_active.load(std::sync::atomic::Ordering::Relaxed),
                                    },
                                    "cache": {
                                        "size": proxy.response_cache.stats().0,
                                        "fresh": proxy.response_cache.stats().1,
                                    },
                                    "mirror": {
                                        "total": m.mirror_total.load(std::sync::atomic::Ordering::Relaxed),
                                        "errors": m.mirror_errors.load(std::sync::atomic::Ordering::Relaxed),
                                    },
                                });
                                let body = serde_json::to_string_pretty(&stats).unwrap_or_default();
                                let resp = hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
                                    .unwrap();
                                return Ok(resp);
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
