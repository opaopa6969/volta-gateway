use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls_acme::caches::DirCache;
use rustls_acme::AcmeConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

use crate::auth::VoltaAuthClient;
use crate::config::TlsConfig;
use crate::metrics;
use crate::proxy::ProxyService;

/// Start HTTPS listener with automatic Let's Encrypt certificates.
pub async fn serve_tls(
    tls_config: &TlsConfig,
    proxy: ProxyService,
    volta_health: VoltaAuthClient,
    metrics: Arc<metrics::Metrics>,
    in_flight: Arc<std::sync::atomic::AtomicUsize>,
) {
    let addr = SocketAddr::from(([0, 0, 0, 0], tls_config.port));

    let cache_dir = tls_config.cache_dir.clone();
    let mut acme = AcmeConfig::new(tls_config.domains.clone())
        .contact(std::iter::once(format!("mailto:{}", tls_config.contact_email)))
        .cache(DirCache::new(cache_dir));

    if tls_config.staging {
        acme = acme.directory_lets_encrypt(false);
    }

    let mut acme_state = acme.state();
    let rustls_config = acme_state.default_rustls_config();

    // Spawn ACME event handler
    tokio::spawn(async move {
        loop {
            match acme_state.next().await {
                Some(Ok(ok)) => info!("ACME event: {:?}", ok),
                Some(Err(err)) => error!("ACME error: {:?}", err),
                None => break,
            }
        }
    });

    let tls_acceptor = TlsAcceptor::from(rustls_config);

    info!(addr = %addr, domains = ?tls_config.domains, "HTTPS/ACME listener starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    loop {
        let (stream, remote_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                error!("TLS accept error: {e}");
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let proxy = proxy.clone();
        let volta_health = volta_health.clone();
        let in_flight = in_flight.clone();
        let metrics = metrics.clone();

        in_flight.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        metrics.active_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        tokio::spawn(async move {
            // TLS handshake
            let tls_stream = match tls_acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    let msg = e.to_string();
                    if !msg.contains("closed") {
                        error!(remote = %remote_addr, "TLS handshake error: {msg}");
                    }
                    in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    metrics.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            };

            let metrics2 = metrics.clone();
            let service = service_fn(move |req: Request<Incoming>| {
                let proxy = proxy.clone();
                let volta_health = volta_health.clone();
                let metrics = metrics2.clone();
                let addr = remote_addr;
                async move {
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

            if let Err(e) = auto::Builder::new(TokioExecutor::new())
                .http1()
                .max_buf_size(10 * 1024 * 1024)
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection_with_upgrades(TokioIo::new(tls_stream), service)
                .await
            {
                let msg = e.to_string();
                if !msg.contains("connection closed") && !msg.contains("incomplete") {
                    error!(remote = %remote_addr, "TLS connection error: {msg}");
                }
            }

            in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            metrics.active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });
    }
}
