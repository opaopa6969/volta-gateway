//! #13: Config Source architecture — pluggable config providers.
//!
//! Sources: YAML (default), services.json (#16), Docker labels (#15), HTTP polling (#17).
//! Each source implements ConfigSource trait and can watch for changes.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use crate::config::RouteEntry;

/// Config Source trait — implement to add new config providers.
#[async_trait::async_trait]
pub trait ConfigSource: Send + Sync {
    fn name(&self) -> &str;
    fn load(&self) -> Result<Vec<RouteEntry>, String>;
    /// Watch for changes. Send new routes on the channel when config changes.
    /// Returns None if watching is not supported.
    async fn watch(&self, tx: mpsc::Sender<Vec<RouteEntry>>);
}

/// Config source type in YAML config.
#[derive(Debug, Clone, Deserialize)]
pub struct ConfigSourceEntry {
    #[serde(rename = "type")]
    pub source_type: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub watch: bool,
    /// services.json specific
    #[serde(default)]
    pub prod_env: Option<String>,
    #[serde(default)]
    pub prod_host: Option<String>,
    /// Docker labels specific
    #[serde(default)]
    pub docker_socket: Option<String>,
}

fn default_poll_interval() -> u64 { 30 }

// ─── #16: services.json Source ──────────────────────────

/// services.json format (volta-platform compatible).
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceEntry {
    pub name: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub public: Option<bool>,
    #[serde(default)]
    pub auth_bypass_paths: Option<Vec<String>>,
    #[serde(default)]
    pub cors_origins: Option<Vec<String>>,
    #[serde(default)]
    pub strip_prefix: Option<String>,
    #[serde(default)]
    pub app_id: Option<String>,
}

pub struct ServicesJsonSource {
    path: String,
    prod_host: String,
}

impl ServicesJsonSource {
    pub fn new(path: &str, prod_host: &str) -> Self {
        Self { path: path.to_string(), prod_host: prod_host.to_string() }
    }

    fn parse_services(&self, content: &str) -> Result<Vec<RouteEntry>, String> {
        let services: Vec<ServiceEntry> = serde_json::from_str(content)
            .map_err(|e| format!("services.json parse error: {}", e))?;

        let mut routes = Vec::new();
        for svc in services {
            let host = match svc.host {
                Some(h) => h,
                None => format!("{}.unlaxer.org", svc.name),
            };
            let port = svc.port.unwrap_or(3000);
            let backend = format!("http://{}:{}", self.prod_host, port);

            let bypass_paths = svc.auth_bypass_paths.unwrap_or_default()
                .into_iter()
                .map(|p| crate::config::BypassPath { prefix: p, backend: None })
                .collect();

            routes.push(RouteEntry {
                host,
                backend: Some(backend),
                backends: vec![],
                app_id: svc.app_id,
                ip_allowlist: vec![],
                cors_origins: svc.cors_origins.unwrap_or_default(),
                path_prefix: None,
                strip_prefix: svc.strip_prefix,
                add_prefix: None,
                request_headers: None,
                response_headers: None,
                geo_allowlist: vec![],
                geo_denylist: vec![],
                public: svc.public.unwrap_or(false),
                auth_bypass_paths: bypass_paths,
                mirror: None,
                cache: None,
                backend_tls: None,
            });
        }
        Ok(routes)
    }
}

#[async_trait::async_trait]
impl ConfigSource for ServicesJsonSource {
    fn name(&self) -> &str { "services-json" }

    fn load(&self) -> Result<Vec<RouteEntry>, String> {
        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| format!("failed to read {}: {}", self.path, e))?;
        self.parse_services(&content)
    }

    async fn watch(&self, tx: mpsc::Sender<Vec<RouteEntry>>) {
        // Simple poll-based watch (inotify would be better but requires extra dep)
        let path = self.path.clone();
        let prod_host = self.prod_host.clone();
        let mut last_modified = std::fs::metadata(&path).ok()
            .and_then(|m| m.modified().ok());

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let current = std::fs::metadata(&path).ok()
                .and_then(|m| m.modified().ok());

            if current != last_modified {
                last_modified = current;
                let source = ServicesJsonSource::new(&path, &prod_host);
                match source.load() {
                    Ok(routes) => {
                        info!(source = "services-json", routes = routes.len(), "config changed");
                        if tx.send(routes).await.is_err() { break; }
                    }
                    Err(e) => warn!(source = "services-json", error = %e, "reload failed"),
                }
            }
        }
    }
}

// ─── #15: Docker Labels Source ──────────────────────────

pub struct DockerLabelsSource {
    socket: String,
}

impl DockerLabelsSource {
    pub fn new(socket: &str) -> Self {
        Self { socket: socket.to_string() }
    }

    /// Parse Docker container labels into RouteEntry.
    /// Expected labels: volta.host, volta.port, volta.public, etc.
    pub fn parse_labels(labels: &HashMap<String, String>, container_ip: &str) -> Option<RouteEntry> {
        let host = labels.get("volta.host")?;
        let port = labels.get("volta.port")
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(3000);

        let public = labels.get("volta.public")
            .map(|v| v == "true")
            .unwrap_or(false);

        let cors: Vec<String> = labels.get("volta.cors_origins")
            .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        let bypass: Vec<crate::config::BypassPath> = labels.get("volta.auth_bypass")
            .map(|s| s.split(',').map(|p| crate::config::BypassPath {
                prefix: p.trim().to_string(), backend: None,
            }).collect())
            .unwrap_or_default();

        Some(RouteEntry {
            host: host.clone(),
            backend: Some(format!("http://{}:{}", container_ip, port)),
            backends: vec![],
            app_id: labels.get("volta.app_id").cloned(),
            ip_allowlist: vec![],
            cors_origins: cors,
            path_prefix: None,
            strip_prefix: labels.get("volta.strip_prefix").cloned(),
            add_prefix: None,
            request_headers: None,
            response_headers: None,
            geo_allowlist: vec![],
            geo_denylist: vec![],
            public,
            auth_bypass_paths: bypass,
            mirror: None,
            cache: None,
            backend_tls: None,
        })
    }
}

#[async_trait::async_trait]
impl ConfigSource for DockerLabelsSource {
    fn name(&self) -> &str { "docker-labels" }

    fn load(&self) -> Result<Vec<RouteEntry>, String> {
        // Docker API via Unix socket — list containers with volta.host label
        // For now, return empty (full Docker API client would require hyper unix socket)
        warn!("Docker labels source: initial load requires Docker API client (not yet implemented). Use services.json for now.");
        Ok(vec![])
    }

    async fn watch(&self, tx: mpsc::Sender<Vec<RouteEntry>>) {
        // Docker events API: GET /events?filters={"type":["container"],"event":["start","stop","die"]}
        warn!("Docker labels watch: Docker events API not yet implemented. Use services.json with watch: true.");
        // Keep task alive
        loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; }
    }
}

// ─── #17: HTTP Polling Source ───────────────────────────

pub struct HttpPollingSource {
    url: String,
    interval_secs: u64,
}

impl HttpPollingSource {
    pub fn new(url: &str, interval_secs: u64) -> Self {
        Self { url: url.to_string(), interval_secs }
    }
}

#[async_trait::async_trait]
impl ConfigSource for HttpPollingSource {
    fn name(&self) -> &str { "http-polling" }

    fn load(&self) -> Result<Vec<RouteEntry>, String> {
        // Sync HTTP fetch for initial load
        // In production, use async. For now, return empty.
        warn!("HTTP polling source: sync initial load not implemented. Routes will be loaded on first poll.");
        Ok(vec![])
    }

    async fn watch(&self, tx: mpsc::Sender<Vec<RouteEntry>>) {
        let client: hyper_util::client::legacy::Client<_, http_body_util::Empty<bytes::Bytes>> =
            hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new()
            ).build_http();

        loop {
            tokio::time::sleep(std::time::Duration::from_secs(self.interval_secs)).await;

            let req = match hyper::Request::builder()
                .uri(self.url.parse::<hyper::Uri>().unwrap_or_default())
                .body(http_body_util::Empty::<bytes::Bytes>::new())
            {
                Ok(r) => r,
                Err(e) => { warn!(source = "http", error = %e, "build request failed"); continue; }
            };

            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client.request(req),
            ).await {
                Ok(Ok(resp)) if resp.status().is_success() => {
                    match http_body_util::BodyExt::collect(resp.into_body()).await {
                        Ok(body) => {
                            let bytes = body.to_bytes();
                            let json_str = String::from_utf8_lossy(&bytes);
                            let source = ServicesJsonSource::new("", "localhost");
                            match source.parse_services(&json_str) {
                                Ok(routes) => {
                                    info!(source = "http", routes = routes.len(), "config polled");
                                    if tx.send(routes).await.is_err() { break; }
                                }
                                Err(e) => warn!(source = "http", error = %e, "parse failed"),
                            }
                        }
                        Err(e) => warn!(source = "http", error = %e, "body read failed"),
                    }
                }
                Ok(Ok(resp)) => warn!(source = "http", status = resp.status().as_u16(), "non-200"),
                Ok(Err(e)) => warn!(source = "http", error = %e, "request failed"),
                Err(_) => warn!(source = "http", "timeout"),
            }
        }
    }
}

// ─── Config Source Manager ──────────────────────────────

/// Manages multiple config sources and merges routes.
pub fn create_sources(entries: &[ConfigSourceEntry]) -> Vec<Box<dyn ConfigSource>> {
    let mut sources: Vec<Box<dyn ConfigSource>> = Vec::new();

    for entry in entries {
        match entry.source_type.as_str() {
            "services-json" => {
                let path = entry.path.as_deref().unwrap_or("services.json");
                let host = entry.prod_host.as_deref().unwrap_or("localhost");
                sources.push(Box::new(ServicesJsonSource::new(path, host)));
                info!(source = "services-json", path = path, "config source registered");
            }
            "docker-labels" => {
                let socket = entry.docker_socket.as_deref().unwrap_or("/var/run/docker.sock");
                sources.push(Box::new(DockerLabelsSource::new(socket)));
                info!(source = "docker-labels", socket = socket, "config source registered");
            }
            "http" => {
                let url = entry.url.as_deref().unwrap_or("http://localhost:5000/api/services");
                sources.push(Box::new(HttpPollingSource::new(url, entry.poll_interval_secs)));
                info!(source = "http", url = url, interval = entry.poll_interval_secs, "config source registered");
            }
            other => {
                warn!(source = other, "unknown config source type, skipping");
            }
        }
    }

    sources
}
