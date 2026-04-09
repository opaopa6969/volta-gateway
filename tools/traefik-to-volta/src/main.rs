//! traefik-to-volta — Convert Traefik config to volta-gateway YAML.
//!
//! Supports:
//! - Docker Compose labels (traefik.http.routers.*, traefik.http.services.*)
//! - Traefik dynamic YAML (http.routers, http.services, http.middlewares)
//!
//! Usage:
//!   traefik-to-volta --from docker-compose --input docker-compose.yml
//!   traefik-to-volta --from traefik-yaml --input dynamic.yaml

use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "traefik-to-volta", about = "Convert Traefik config to volta-gateway YAML")]
struct Cli {
    /// Input format: docker-compose | traefik-yaml
    #[arg(long, default_value = "docker-compose")]
    from: String,

    /// Input file path
    #[arg(long)]
    input: String,

    /// Output file path (default: stdout)
    #[arg(long)]
    output: Option<String>,
}

// ─── volta-gateway output format ───────────────────────

#[derive(Debug, Serialize)]
struct VoltaConfig {
    server: VoltaServer,
    auth: VoltaAuth,
    routing: Vec<VoltaRoute>,
}

#[derive(Debug, Serialize)]
struct VoltaServer {
    port: u16,
}

#[derive(Debug, Serialize)]
struct VoltaAuth {
    volta_url: String,
}

#[derive(Debug, Serialize)]
struct VoltaRoute {
    host: String,
    backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_id: Option<String>,
    #[serde(skip_serializing_if = "is_false")]
    public: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cors_origins: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strip_prefix: Option<String>,
}

fn is_false(b: &bool) -> bool { !*b }

// ─── Docker Compose parser ─────────────────────────────

fn parse_docker_compose(content: &str) -> Vec<VoltaRoute> {
    let doc: serde_yaml::Value = serde_yaml::from_str(content)
        .expect("invalid YAML");

    let mut routes = Vec::new();
    let services = doc.get("services").and_then(|s| s.as_mapping());

    if let Some(services) = services {
        for (name, service) in services {
            let name = name.as_str().unwrap_or("unknown");
            let labels = service.get("labels");

            if let Some(labels) = labels {
                let label_map = extract_labels(labels);
                if let Some(route) = labels_to_route(name, &label_map) {
                    routes.push(route);
                }
            }
        }
    }
    routes
}

fn extract_labels(labels: &serde_yaml::Value) -> HashMap<String, String> {
    let mut map = HashMap::new();
    match labels {
        serde_yaml::Value::Sequence(seq) => {
            for item in seq {
                if let Some(s) = item.as_str() {
                    if let Some((k, v)) = s.split_once('=') {
                        map.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }
        serde_yaml::Value::Mapping(m) => {
            for (k, v) in m {
                if let (Some(k), Some(v)) = (k.as_str(), v.as_str()) {
                    map.insert(k.to_string(), v.to_string());
                }
            }
        }
        _ => {}
    }
    map
}

fn labels_to_route(service_name: &str, labels: &HashMap<String, String>) -> Option<VoltaRoute> {
    // Find host rule: traefik.http.routers.<name>.rule = Host(`example.com`)
    let host_re = Regex::new(r"Host\(`([^`]+)`\)").unwrap();

    let mut host = None;
    let mut has_forward_auth = false;
    let mut strip_prefix = None;
    let mut cors_origins = Vec::new();
    let mut port = "3000".to_string();

    for (key, value) in labels {
        if key.contains(".rule") && key.starts_with("traefik.http.routers.") {
            if let Some(caps) = host_re.captures(value) {
                host = Some(caps[1].to_string());
            }
        }
        if key.contains(".middlewares") && value.contains("forward-auth") {
            has_forward_auth = true;
        }
        if key.contains("stripprefix.prefixes") {
            strip_prefix = Some(value.clone());
        }
        if key.contains(".loadbalancer.server.port") {
            port = value.clone();
        }
        if key.contains("headers.accesscontrolalloworiginlist") {
            cors_origins = value.split(',').map(|s| s.trim().to_string()).collect();
        }
    }

    let host = host?;
    Some(VoltaRoute {
        host: host.clone(),
        backend: format!("http://{}:{}", service_name, port),
        app_id: Some(service_name.to_string()),
        public: !has_forward_auth,
        cors_origins,
        strip_prefix,
    })
}

// ─── Traefik dynamic YAML parser ───────────────────────

fn parse_traefik_yaml(content: &str) -> Vec<VoltaRoute> {
    let doc: serde_yaml::Value = serde_yaml::from_str(content)
        .expect("invalid YAML");

    let mut routes = Vec::new();
    let routers = doc.get("http").and_then(|h| h.get("routers")).and_then(|r| r.as_mapping());
    let services = doc.get("http").and_then(|h| h.get("services")).and_then(|s| s.as_mapping());
    let middlewares = doc.get("http").and_then(|h| h.get("middlewares")).and_then(|m| m.as_mapping());

    let host_re = Regex::new(r"Host\(`([^`]+)`\)").unwrap();

    if let Some(routers) = routers {
        for (name, router) in routers {
            let name = name.as_str().unwrap_or("unknown");
            let rule = router.get("rule").and_then(|r| r.as_str()).unwrap_or("");
            let service_name = router.get("service").and_then(|s| s.as_str()).unwrap_or(name);

            let host = host_re.captures(rule).map(|c| c[1].to_string());
            if host.is_none() { continue; }
            let host = host.unwrap();

            // Check if ForwardAuth middleware is used
            let mw_list: Vec<String> = router.get("middlewares")
                .and_then(|m| m.as_sequence())
                .map(|seq| seq.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            let has_auth = mw_list.iter().any(|m| {
                middlewares.and_then(|mws| mws.get(serde_yaml::Value::String(m.clone())))
                    .and_then(|mw| mw.get("forwardAuth"))
                    .is_some()
            });

            // Find backend URL
            let backend = services
                .and_then(|svcs| svcs.get(serde_yaml::Value::String(service_name.to_string())))
                .and_then(|svc| svc.get("loadBalancer"))
                .and_then(|lb| lb.get("servers"))
                .and_then(|servers| servers.as_sequence())
                .and_then(|seq| seq.first())
                .and_then(|s| s.get("url"))
                .and_then(|u| u.as_str())
                .unwrap_or("http://localhost:3000")
                .to_string();

            routes.push(VoltaRoute {
                host,
                backend,
                app_id: Some(name.to_string()),
                public: !has_auth,
                cors_origins: vec![],
                strip_prefix: None,
            });
        }
    }
    routes
}

// ─── Main ──────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let content = std::fs::read_to_string(&cli.input)
        .unwrap_or_else(|e| { eprintln!("Error reading {}: {}", cli.input, e); std::process::exit(1); });

    let routes = match cli.from.as_str() {
        "docker-compose" => parse_docker_compose(&content),
        "traefik-yaml" => parse_traefik_yaml(&content),
        other => { eprintln!("Unknown format: {}. Use docker-compose or traefik-yaml.", other); std::process::exit(1); }
    };

    let config = VoltaConfig {
        server: VoltaServer { port: 8080 },
        auth: VoltaAuth { volta_url: "http://localhost:7070".into() },
        routing: routes,
    };

    let yaml = serde_yaml::to_string(&config).unwrap();

    if let Some(output) = cli.output {
        std::fs::write(&output, &yaml).unwrap();
        eprintln!("Written to {}", output);
    } else {
        println!("{}", yaml);
    }

    eprintln!("Converted {} routes.", config.routing.len());
}
