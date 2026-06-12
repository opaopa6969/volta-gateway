//! Tests for ConfigSource (#13), services.json (#16), Docker labels (#15),
//! MiddlewareExtension (#14), and cache integration.

use std::collections::HashMap;

// ─── services.json Parsing (#16) ───────────────────────

#[test]
fn services_json_parses_basic() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "192.168.1.50");
    let json = r#"[
        {"name": "console", "port": 3789},
        {"name": "auth", "port": 7070, "public": true},
        {"name": "dve", "port": 4173, "auth_bypass_paths": ["/api/slack/"]}
    ]"#;

    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes.len(), 3);

    // console
    assert_eq!(routes[0].host, "console.unlaxer.org");
    assert_eq!(routes[0].backend.as_ref().unwrap(), "http://192.168.1.50:3789");
    assert!(!routes[0].public);

    // auth
    assert_eq!(routes[1].host, "auth.unlaxer.org");
    assert!(routes[1].public);

    // dve with bypass
    assert_eq!(routes[2].auth_bypass_paths.len(), 1);
    assert_eq!(routes[2].auth_bypass_paths[0].prefix, "/api/slack/");
}

#[test]
fn services_json_custom_host() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "10.0.0.5");
    let json = r#"[{"name": "api", "host": "api.custom.com", "port": 8080}]"#;

    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes[0].host, "api.custom.com");
    assert_eq!(routes[0].backend.as_ref().unwrap(), "http://10.0.0.5:8080");
}

#[test]
fn services_json_defaults() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "localhost");
    let json = r#"[{"name": "app"}]"#;

    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes[0].host, "app.unlaxer.org");
    assert_eq!(routes[0].backend.as_ref().unwrap(), "http://localhost:3000"); // default port
    assert!(!routes[0].public); // default false
}

#[test]
fn services_json_with_cors_and_strip() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "localhost");
    let json = r#"[{
        "name": "api",
        "port": 4000,
        "cors_origins": ["https://app.example.com"],
        "strip_prefix": "/api/v1",
        "app_id": "my-api"
    }]"#;

    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes[0].cors_origins, vec!["https://app.example.com"]);
    assert_eq!(routes[0].strip_prefix.as_ref().unwrap(), "/api/v1");
    assert_eq!(routes[0].app_id.as_ref().unwrap(), "my-api");
}

#[test]
fn services_json_invalid_json_returns_error() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "localhost");
    let result = source.parse_services("not json");
    assert!(result.is_err());
}

// ─── Console (volta-platform) format (#16) ─────────────

const CONSOLE_FIXTURE: &str = include_str!("fixtures/console_services.json");

#[test]
fn console_format_converts_seed_entries() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "192.168.1.50");
    let routes = source.parse_services(CONSOLE_FIXTURE).unwrap();

    // 5 services in fixture: 2 skipped (nexus prod.enabled=false,
    // intellij-xpra cloudflare.enabled=false) → 3 routes.
    assert_eq!(routes.len(), 3, "disabled services must be skipped");

    let by_host = |h: &str| routes.iter().find(|r| r.host == h)
        .unwrap_or_else(|| panic!("missing route {h}"));

    // netmahg: public via top-level public + access.visibility=public.
    let mahjong = by_host("mahjong.unlaxer.org");
    assert_eq!(mahjong.backend.as_ref().unwrap(), "http://192.168.1.50:7074");
    assert!(mahjong.public);
    assert!(mahjong.app_id.is_none(), "public service gets no app_id");

    // work-os: authenticated (cloudflare.authentication) + not public → app_id = key.
    let work = by_host("work.unlaxer.org");
    assert_eq!(work.backend.as_ref().unwrap(), "http://192.168.1.50:5043");
    assert!(!work.public);
    assert_eq!(work.app_id.as_deref(), Some("work-os"));

    // japanpost-history: explicit env.host overrides default backend host,
    // public, and an auth bypass path.
    let post = by_host("postcode.unlaxer.org");
    assert_eq!(post.backend.as_ref().unwrap(), "http://192.168.1.50:7073");
    assert!(post.public);
    assert_eq!(post.auth_bypass_paths.len(), 1);
    assert_eq!(post.auth_bypass_paths[0].prefix, "/api/lookup/");
}

#[test]
fn console_format_skips_disabled_without_failing() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "10.0.0.1");
    // nexus (prod.enabled=false) and intellij-xpra (cloudflare.enabled=false)
    // must not appear, but the whole parse must still succeed.
    let routes = source.parse_services(CONSOLE_FIXTURE).unwrap();
    assert!(routes.iter().all(|r| r.host != "nexus.unlaxer.org"));
    assert!(!routes.is_empty());
}

#[test]
fn console_format_missing_port_is_skipped_not_fatal() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "10.0.0.1");
    // A service with a prod env but no port can't form a backend → skip,
    // while the convertible neighbour still comes through.
    let json = r#"{
        "broken": {
            "environments": { "prod": { "runtime": "systemd" } },
            "cloudflare": { "enabled": true, "hostname": "broken.unlaxer.org" }
        },
        "ok": {
            "environments": { "prod": { "port": 9000 } },
            "cloudflare": { "enabled": true, "hostname": "ok.unlaxer.org" }
        }
    }"#;
    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].host, "ok.unlaxer.org");
}

#[test]
fn console_format_per_env_hostname_takes_precedence() {
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "10.0.0.1");
    let json = r#"{
        "svc": {
            "environments": { "prod": { "port": 8080 } },
            "cloudflare": {
                "enabled": true,
                "hostname": "fallback.unlaxer.org",
                "hostnames": { "prod": "prod.unlaxer.org" }
            }
        }
    }"#;
    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].host, "prod.unlaxer.org");
}

#[test]
fn legacy_array_format_still_works() {
    // The array format must keep parsing unchanged after console support.
    let source = volta_gateway::config_source::ServicesJsonSource::new("/dummy", "192.168.1.50");
    let json = r#"[{"name": "console", "port": 3789}]"#;
    let routes = source.parse_services(json).unwrap();
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].host, "console.unlaxer.org");
    assert_eq!(routes[0].backend.as_ref().unwrap(), "http://192.168.1.50:3789");
}

// ─── services.json watch / hot-reload (#16) ────────────

#[tokio::test]
async fn services_json_watch_initial_load_and_reload() {
    use std::io::Write;
    use tokio::sync::mpsc;

    // Write a temp services.json (console format).
    let dir = std::env::temp_dir().join(format!("volta-watch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("services.json");
    let write = |body: &str| {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    };
    write(r#"{"a": {"environments": {"prod": {"port": 1000}},
        "cloudflare": {"enabled": true, "hostname": "a.unlaxer.org"}}}"#);

    let source = volta_gateway::config_source::ServicesJsonSource::new(
        path.to_str().unwrap(), "127.0.0.1").with_watch(true);

    let (tx, mut rx) = mpsc::channel(4);
    let handle = tokio::spawn(async move {
        use volta_gateway::config_source::ConfigSource;
        source.watch(tx).await;
    });

    // Initial load arrives immediately.
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await.expect("initial load timed out").unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].host, "a.unlaxer.org");

    // Modify the file → poll-based watch picks it up.
    // Sleep past the mtime granularity / poll interval before rewriting.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    write(r#"{
        "a": {"environments": {"prod": {"port": 1000}},
            "cloudflare": {"enabled": true, "hostname": "a.unlaxer.org"}},
        "b": {"environments": {"prod": {"port": 2000}},
            "cloudflare": {"enabled": true, "hostname": "b.unlaxer.org"}}
    }"#);

    let second = tokio::time::timeout(std::time::Duration::from_secs(8), rx.recv())
        .await.expect("reload timed out").unwrap();
    assert_eq!(second.len(), 2, "watch should pick up the added service");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn services_json_no_watch_loads_once_then_stops() {
    use std::io::Write;
    use tokio::sync::mpsc;

    let dir = std::env::temp_dir().join(format!("volta-nowatch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("services.json");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(br#"[{"name": "x", "port": 1234}]"#).unwrap();
    }

    // Default (watch=false): one push, then the watch task returns.
    let source = volta_gateway::config_source::ServicesJsonSource::new(
        path.to_str().unwrap(), "127.0.0.1");

    let (tx, mut rx) = mpsc::channel(4);
    {
        use volta_gateway::config_source::ConfigSource;
        source.watch(tx).await; // returns after the single initial load
    }

    let first = rx.recv().await.unwrap();
    assert_eq!(first.len(), 1);
    // Channel closed (sender dropped) → no further messages.
    assert!(rx.recv().await.is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Docker Labels Parsing (#15) ───────────────────────

#[test]
fn docker_labels_basic() {
    let mut labels = HashMap::new();
    labels.insert("volta.host".into(), "app.unlaxer.org".into());
    labels.insert("volta.port".into(), "3000".into());

    let route = volta_gateway::config_source::DockerLabelsSource::parse_labels(&labels, "172.17.0.2");
    assert!(route.is_some());
    let route = route.unwrap();
    assert_eq!(route.host, "app.unlaxer.org");
    assert_eq!(route.backend.as_ref().unwrap(), "http://172.17.0.2:3000");
}

#[test]
fn docker_labels_public_and_bypass() {
    let mut labels = HashMap::new();
    labels.insert("volta.host".into(), "auth.unlaxer.org".into());
    labels.insert("volta.port".into(), "7070".into());
    labels.insert("volta.public".into(), "true".into());
    labels.insert("volta.auth_bypass".into(), "/api/webhook/,/api/slack/".into());

    let route = volta_gateway::config_source::DockerLabelsSource::parse_labels(&labels, "172.17.0.3").unwrap();
    assert!(route.public);
    assert_eq!(route.auth_bypass_paths.len(), 2);
    assert_eq!(route.auth_bypass_paths[0].prefix, "/api/webhook/");
    assert_eq!(route.auth_bypass_paths[1].prefix, "/api/slack/");
}

#[test]
fn docker_labels_with_cors_and_strip() {
    let mut labels = HashMap::new();
    labels.insert("volta.host".into(), "api.unlaxer.org".into());
    labels.insert("volta.cors_origins".into(), "https://app.unlaxer.org, https://admin.unlaxer.org".into());
    labels.insert("volta.strip_prefix".into(), "/api/v1".into());
    labels.insert("volta.app_id".into(), "myapp".into());

    let route = volta_gateway::config_source::DockerLabelsSource::parse_labels(&labels, "172.17.0.4").unwrap();
    assert_eq!(route.cors_origins.len(), 2);
    assert_eq!(route.cors_origins[0], "https://app.unlaxer.org");
    assert_eq!(route.strip_prefix.as_ref().unwrap(), "/api/v1");
    assert_eq!(route.app_id.as_ref().unwrap(), "myapp");
}

#[test]
fn docker_labels_missing_host_returns_none() {
    let labels = HashMap::new(); // no volta.host
    let route = volta_gateway::config_source::DockerLabelsSource::parse_labels(&labels, "172.17.0.2");
    assert!(route.is_none());
}

#[test]
fn docker_labels_default_port() {
    let mut labels = HashMap::new();
    labels.insert("volta.host".into(), "app.unlaxer.org".into());
    // no volta.port → default 3000

    let route = volta_gateway::config_source::DockerLabelsSource::parse_labels(&labels, "172.17.0.2").unwrap();
    assert_eq!(route.backend.as_ref().unwrap(), "http://172.17.0.2:3000");
}

// ─── MiddlewareExtension (#14) ─────────────────────────

#[tokio::test]
async fn middleware_jwt_rejects_missing_auth() {
    use volta_gateway::middleware_ext::{MiddlewareExtension, ExtensionContext, builtin::JwtValidator};

    let ext = JwtValidator { secret: "test".into(), issuer: None };
    let mut ctx = ExtensionContext {
        method: "GET".into(), host: "api.test.com".into(), path: "/data".into(),
        query: None, headers: HashMap::new(), client_ip: "1.2.3.4".into(),
        user_id: None, tenant_id: None, reject: None,
        add_headers: HashMap::new(), remove_headers: vec![], metadata: HashMap::new(),
    };

    let result = ext.on_request(&mut ctx).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().status, 401);
}

#[tokio::test]
async fn middleware_jwt_rejects_non_bearer() {
    use volta_gateway::middleware_ext::{MiddlewareExtension, ExtensionContext, builtin::JwtValidator};

    let ext = JwtValidator { secret: "test".into(), issuer: None };
    let mut ctx = ExtensionContext {
        method: "GET".into(), host: "api.test.com".into(), path: "/data".into(),
        query: None,
        headers: { let mut h = HashMap::new(); h.insert("authorization".into(), "Basic abc".into()); h },
        client_ip: "1.2.3.4".into(),
        user_id: None, tenant_id: None, reject: None,
        add_headers: HashMap::new(), remove_headers: vec![], metadata: HashMap::new(),
    };

    let result = ext.on_request(&mut ctx).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn middleware_jwt_accepts_bearer_token() {
    use volta_gateway::middleware_ext::{MiddlewareExtension, ExtensionContext, builtin::JwtValidator};

    let ext = JwtValidator { secret: "test".into(), issuer: None };
    let mut ctx = ExtensionContext {
        method: "GET".into(), host: "api.test.com".into(), path: "/data".into(),
        query: None,
        headers: { let mut h = HashMap::new(); h.insert("authorization".into(), "Bearer eyJhbGciOi...".into()); h },
        client_ip: "1.2.3.4".into(),
        user_id: None, tenant_id: None, reject: None,
        add_headers: HashMap::new(), remove_headers: vec![], metadata: HashMap::new(),
    };

    let result = ext.on_request(&mut ctx).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn middleware_request_id_adds_if_missing() {
    use volta_gateway::middleware_ext::{MiddlewareExtension, ExtensionContext, builtin::RequestIdPropagation};

    let ext = RequestIdPropagation;
    let mut ctx = ExtensionContext {
        method: "GET".into(), host: "test.com".into(), path: "/".into(),
        query: None, headers: HashMap::new(), client_ip: "1.2.3.4".into(),
        user_id: None, tenant_id: None, reject: None,
        add_headers: HashMap::new(), remove_headers: vec![], metadata: HashMap::new(),
    };

    ext.on_request(&mut ctx).await.unwrap();
    assert!(ctx.add_headers.contains_key("x-request-id"));
}

#[tokio::test]
async fn middleware_request_id_preserves_existing() {
    use volta_gateway::middleware_ext::{MiddlewareExtension, ExtensionContext, builtin::RequestIdPropagation};

    let ext = RequestIdPropagation;
    let mut ctx = ExtensionContext {
        method: "GET".into(), host: "test.com".into(), path: "/".into(),
        query: None,
        headers: { let mut h = HashMap::new(); h.insert("x-request-id".into(), "existing-id".into()); h },
        client_ip: "1.2.3.4".into(),
        user_id: None, tenant_id: None, reject: None,
        add_headers: HashMap::new(), remove_headers: vec![], metadata: HashMap::new(),
    };

    ext.on_request(&mut ctx).await.unwrap();
    assert!(!ctx.add_headers.contains_key("x-request-id")); // should NOT override
}

// ─── Config Source creation ────────────────────────────

#[test]
fn config_sources_parse_from_yaml() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: app.example.com
    backend: http://localhost:3000
config_sources:
  - type: services-json
    path: /app/services.json
    prod_host: "192.168.1.50"
    watch: true
  - type: http
    url: http://volta-console:5000/api/services
    poll_interval_secs: 60
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.config_sources.len(), 2);
    assert_eq!(config.config_sources[0].source_type, "services-json");
    assert_eq!(config.config_sources[1].source_type, "http");
    assert_eq!(config.config_sources[1].poll_interval_secs, 60);
}

// ─── SIGHUP × services.json root-cause fix (Phase 1) ────
//
// rebuild_hot (SIGHUP / admin reload) used to rebuild HotState from the static
// YAML only, so services.json-derived routes vanished until the next watcher
// push. spawn_watchers now publishes its routes into a shared DynamicRoutes
// snapshot, and rebuild_hot_with_dynamic re-merges them on rebuild.

#[tokio::test]
async fn sighup_rebuild_keeps_services_json_routes() {
    use std::sync::Arc;
    use arc_swap::ArcSwap;
    use volta_gateway::config::GatewayConfig;
    use volta_gateway::config_source::{create_sources, spawn_watchers};
    use volta_gateway::config_overlay::{new_dynamic_routes, rebuild_hot_with_dynamic};
    use volta_gateway::proxy::HotState;

    // Static YAML route + a services.json config source.
    let dir = std::env::temp_dir().join(format!("volta_sighup_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let svc_path = dir.join("services.json");
    std::fs::write(&svc_path, r#"[{"name": "console", "host": "console.example.com", "port": 3789}]"#).unwrap();

    let yaml = format!(r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: static.example.com
    backend: http://localhost:3000
config_sources:
  - type: services-json
    path: "{}"
    prod_host: "192.168.1.50"
"#, svc_path.display());
    let config: GatewayConfig = serde_yaml::from_str(&yaml).unwrap();

    // Build the initial HotState (static only), then start watchers which publish
    // the services.json route into both HotState and the shared dynamic snapshot.
    let hot: Arc<ArcSwap<HotState>> = Arc::new(ArcSwap::from_pointee(
        HotState::new(Arc::new(config.routing_table())),
    ));
    let dynamic = new_dynamic_routes();
    let sources = create_sources(&config.config_sources);
    spawn_watchers(sources, hot.clone(), &config, dynamic.clone());

    // Wait for the initial services.json load to land in HotState.
    let mut merged_ok = false;
    for _ in 0..50 {
        if hot.load().routing.contains_key("console.example.com") {
            merged_ok = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(merged_ok, "services.json route should appear in HotState after watcher start");
    assert!(hot.load().routing.contains_key("static.example.com"));

    // Simulate a SIGHUP: rebuild HotState from the (reloaded) static config while
    // re-merging the dynamic snapshot.
    rebuild_hot_with_dynamic(&config, &hot, &dynamic);

    let snap = hot.load();
    assert!(snap.routing.contains_key("static.example.com"),
        "static route survives SIGHUP rebuild");
    assert!(snap.routing.contains_key("console.example.com"),
        "services.json route survives SIGHUP rebuild (root-cause fix — was the bug)");
}
