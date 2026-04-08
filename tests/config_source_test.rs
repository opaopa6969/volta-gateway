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
