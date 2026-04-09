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

    pub fn parse_services(&self, content: &str) -> Result<Vec<RouteEntry>, String> {
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
                timeout_secs: None,
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
            timeout_secs: None,
            cache: None,
            backend_tls: None,
        })
    }
}

#[async_trait::async_trait]
impl ConfigSource for DockerLabelsSource {
    fn name(&self) -> &str { "docker-labels" }

    fn load(&self) -> Result<Vec<RouteEntry>, String> {
        // Synchronous initial load — use tokio block_on for Docker API call.
        // This runs once at startup before the async runtime is fully active for this source.
        let socket = self.socket.clone();
        let rt = tokio::runtime::Handle::try_current();
        match rt {
            Ok(handle) => {
                // We're already in a tokio context — spawn blocking to avoid nested runtime.
                let routes = std::thread::scope(|_| {
                    let docker = bollard::Docker::connect_with_socket(&socket, 120, bollard::API_DEFAULT_VERSION)
                        .map_err(|e| format!("docker connect: {}", e))?;
                    handle.block_on(Self::load_from_docker(&docker))
                });
                routes
            }
            Err(_) => {
                warn!("Docker labels source: no tokio runtime for initial load, returning empty.");
                Ok(vec![])
            }
        }
    }

    async fn watch(&self, tx: mpsc::Sender<Vec<RouteEntry>>) {
        use bollard::system::EventsOptions;
        use futures::StreamExt;

        let docker = match bollard::Docker::connect_with_socket(&self.socket, 120, bollard::API_DEFAULT_VERSION) {
            Ok(d) => d,
            Err(e) => {
                error!(source = "docker-labels", error = %e, "failed to connect to Docker");
                return;
            }
        };

        info!(source = "docker-labels", socket = %self.socket, "watching Docker events");

        // Filter for container start/stop/die events
        let mut filters = HashMap::new();
        filters.insert("type", vec!["container"]);
        filters.insert("event", vec!["start", "stop", "die"]);
        let options = EventsOptions { filters, ..Default::default() };

        let mut stream = docker.events(Some(options));

        while let Some(event) = stream.next().await {
            match event {
                Ok(ev) => {
                    info!(
                        source = "docker-labels",
                        action = ev.action.as_deref().unwrap_or("?"),
                        "container event — reloading routes"
                    );
                    match Self::load_from_docker(&docker).await {
                        Ok(routes) => {
                            if tx.send(routes).await.is_err() { break; }
                        }
                        Err(e) => warn!(source = "docker-labels", error = %e, "reload failed"),
                    }
                }
                Err(e) => {
                    warn!(source = "docker-labels", error = %e, "event stream error");
                    // Reconnect delay
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
}

impl DockerLabelsSource {
    /// Load routes from Docker API — list running containers with `volta.host` label.
    async fn load_from_docker(docker: &bollard::Docker) -> Result<Vec<RouteEntry>, String> {
        use bollard::container::ListContainersOptions;

        let mut filters = HashMap::new();
        filters.insert("status", vec!["running"]);
        filters.insert("label", vec!["volta.host"]);

        let options = ListContainersOptions { filters, ..Default::default() };

        let containers = docker.list_containers(Some(options)).await
            .map_err(|e| format!("docker list: {}", e))?;

        let mut routes = Vec::new();
        for c in &containers {
            let labels = match &c.labels {
                Some(l) => l.clone(),
                None => continue,
            };

            // Get container IP from first network, or fall back to container name
            let ip = c.network_settings.as_ref()
                .and_then(|ns| ns.networks.as_ref())
                .and_then(|nets| nets.values().next())
                .and_then(|net| net.ip_address.as_deref())
                .unwrap_or("127.0.0.1");

            if let Some(route) = Self::parse_labels(&labels, ip) {
                info!(
                    source = "docker-labels",
                    host = %route.host,
                    backend = route.backend.as_deref().unwrap_or("?"),
                    "discovered route"
                );
                routes.push(route);
            }
        }

        info!(source = "docker-labels", count = routes.len(), "loaded routes from Docker");
        Ok(routes)
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

/// Spawn config source watchers and merge dynamic routes into ArcSwap<HotState>.
///
/// Each source's watch() sends Vec<RouteEntry> on change.
/// The watcher merges dynamic routes with static YAML routes and updates HotState.
pub fn spawn_watchers(
    sources: Vec<Box<dyn ConfigSource>>,
    hot: Arc<arc_swap::ArcSwap<crate::proxy::HotState>>,
    config: &crate::config::GatewayConfig,
) {
    use crate::proxy::HotState;

    let static_routing = Arc::new(config.routing_table());
    let static_allowlists = config.ip_allowlist_table();
    let static_cors = config.cors_table();
    let trusted_proxies: Vec<ipnet::IpNet> = config.server.trusted_proxies.iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let error_pages_dir = config.error_pages_dir.clone();

    for source in sources {
        let (tx, mut rx) = mpsc::channel::<Vec<RouteEntry>>(16);
        let name = source.name().to_string();

        // Spawn the source's watch task
        tokio::spawn(async move {
            source.watch(tx).await;
        });

        // Spawn the merge task
        let hot = hot.clone();
        let static_routing = static_routing.clone();
        let static_allowlists = static_allowlists.clone();
        let static_cors = static_cors.clone();
        let trusted_proxies = trusted_proxies.clone();
        let error_pages_dir = error_pages_dir.clone();

        tokio::spawn(async move {
            while let Some(dynamic_routes) = rx.recv().await {
                // Start from static routes
                let mut merged = (*static_routing).clone();

                // Merge dynamic routes (dynamic overwrites static on host conflict)
                for route in &dynamic_routes {
                    let info = crate::proxy::RouteInfo {
                        backends: route.all_backends(),
                        weights: route.all_weights(),
                        app_id: route.app_id.clone(),
                        public: route.public,
                        bypass_paths: route.auth_bypass_paths.clone(),
                        mirror: route.mirror.clone(),
                        path_prefix: route.path_prefix.clone(),
                        strip_prefix: route.strip_prefix.clone(),
                        add_prefix: route.add_prefix.clone(),
                        request_headers: route.request_headers.clone(),
                        response_headers: route.response_headers.clone(),
                        geo_allowlist: route.geo_allowlist.clone(),
                        geo_denylist: route.geo_denylist.clone(),
                        timeout_secs: route.timeout_secs,
                        cache: route.cache.clone(),
                        backend_tls: route.backend_tls.clone(),
                    };
                    merged.insert(route.host.to_lowercase(), info);
                }

                let route_count = merged.len();
                let new_hot = HotState::new_full(
                    Arc::new(merged),
                    static_allowlists.clone(),
                    error_pages_dir.as_deref(),
                    static_cors.clone(),
                    trusted_proxies.clone(),
                );
                hot.store(Arc::new(new_hot));

                info!(
                    source = %name,
                    dynamic = dynamic_routes.len(),
                    total = route_count,
                    "routes merged from config source"
                );
            }
        });
    }
}

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
