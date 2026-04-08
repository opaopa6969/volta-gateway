//! Tests for #8 (cache), #9 (mTLS config), #11 (plugin system)

use std::collections::HashMap;
use std::time::Duration;

// ─── Cache Tests (#8) ──────────────────────────────────

#[test]
fn cache_put_and_get() {
    let cache = volta_gateway::cache::ResponseCache::new(100);
    let key = volta_gateway::cache::ResponseCache::key("GET", "docs.test.com", "/page", None, false);

    cache.put(
        key.clone(), 200,
        vec![("content-type".into(), "text/html".into())],
        bytes::Bytes::from("<h1>hello</h1>"),
        Duration::from_secs(300),
    );

    let result = cache.get(&key);
    assert!(result.is_some());
    let (status, headers, body) = result.unwrap();
    assert_eq!(status, 200);
    assert_eq!(headers[0].1, "text/html");
    assert_eq!(body, "<h1>hello</h1>");
}

#[test]
fn cache_miss_on_unknown_key() {
    let cache = volta_gateway::cache::ResponseCache::new(100);
    assert!(cache.get("unknown").is_none());
}

#[test]
fn cache_expires_after_ttl() {
    let cache = volta_gateway::cache::ResponseCache::new(100);
    let key = "GET:test:/:".to_string();

    cache.put(
        key.clone(), 200, vec![], bytes::Bytes::new(),
        Duration::from_millis(1), // 1ms TTL
    );

    std::thread::sleep(Duration::from_millis(10));
    assert!(cache.get(&key).is_none(), "should be expired");
}

#[test]
fn cache_lru_eviction() {
    let cache = volta_gateway::cache::ResponseCache::new(2); // max 2 entries

    cache.put("k1".into(), 200, vec![], bytes::Bytes::new(), Duration::from_secs(300));
    cache.put("k2".into(), 200, vec![], bytes::Bytes::new(), Duration::from_secs(300));
    cache.put("k3".into(), 200, vec![], bytes::Bytes::new(), Duration::from_secs(300));

    // k1 should be evicted (oldest)
    assert!(cache.get("k1").is_none());
    assert!(cache.get("k2").is_some());
    assert!(cache.get("k3").is_some());
}

#[test]
fn cache_key_includes_query() {
    let k1 = volta_gateway::cache::ResponseCache::key("GET", "api.test.com", "/search", Some("q=foo"), false);
    let k2 = volta_gateway::cache::ResponseCache::key("GET", "api.test.com", "/search", Some("q=bar"), false);
    assert_ne!(k1, k2);
}

#[test]
fn cache_key_ignores_query_when_configured() {
    let k1 = volta_gateway::cache::ResponseCache::key("GET", "api.test.com", "/search", Some("q=foo"), true);
    let k2 = volta_gateway::cache::ResponseCache::key("GET", "api.test.com", "/search", Some("q=bar"), true);
    assert_eq!(k1, k2);
}

#[test]
fn cache_control_no_store_not_cacheable() {
    assert!(!volta_gateway::cache::is_cacheable(Some("no-store")));
    assert!(!volta_gateway::cache::is_cacheable(Some("private, no-store")));
    assert!(volta_gateway::cache::is_cacheable(Some("max-age=3600")));
    assert!(volta_gateway::cache::is_cacheable(None));
}

#[test]
fn cache_stats() {
    let cache = volta_gateway::cache::ResponseCache::new(100);
    cache.put("k1".into(), 200, vec![], bytes::Bytes::new(), Duration::from_secs(300));
    cache.put("k2".into(), 200, vec![], bytes::Bytes::new(), Duration::from_secs(300));
    let (total, fresh) = cache.stats();
    assert_eq!(total, 2);
    assert_eq!(fresh, 2);
}

// ─── Plugin Tests (#11) ────────────────────────────────

#[test]
fn plugin_api_key_auth_accepts_valid() {
    use volta_gateway::plugin::{Plugin, PluginContext, builtin::ApiKeyAuth};

    let plugin = ApiKeyAuth {
        header: "x-api-key".into(),
        valid_keys: vec!["secret123".into()],
    };

    let mut ctx = PluginContext {
        method: "GET".into(), host: "api.test.com".into(), path: "/data".into(),
        headers: {
            let mut h = HashMap::new();
            h.insert("x-api-key".into(), "secret123".into());
            h
        },
        client_ip: "1.2.3.4".into(),
        reject: None, add_headers: HashMap::new(), remove_headers: vec![],
    };

    plugin.on_request(&mut ctx).unwrap();
    assert!(ctx.reject.is_none());
}

#[test]
fn plugin_api_key_auth_rejects_invalid() {
    use volta_gateway::plugin::{Plugin, PluginContext, builtin::ApiKeyAuth};

    let plugin = ApiKeyAuth {
        header: "x-api-key".into(),
        valid_keys: vec!["secret123".into()],
    };

    let mut ctx = PluginContext {
        method: "GET".into(), host: "api.test.com".into(), path: "/data".into(),
        headers: {
            let mut h = HashMap::new();
            h.insert("x-api-key".into(), "wrong".into());
            h
        },
        client_ip: "1.2.3.4".into(),
        reject: None, add_headers: HashMap::new(), remove_headers: vec![],
    };

    plugin.on_request(&mut ctx).unwrap();
    assert!(ctx.reject.is_some());
    assert_eq!(ctx.reject.unwrap().0, 403);
}

#[test]
fn plugin_api_key_auth_rejects_missing() {
    use volta_gateway::plugin::{Plugin, PluginContext, builtin::ApiKeyAuth};

    let plugin = ApiKeyAuth {
        header: "x-api-key".into(),
        valid_keys: vec!["secret123".into()],
    };

    let mut ctx = PluginContext {
        method: "GET".into(), host: "api.test.com".into(), path: "/data".into(),
        headers: HashMap::new(),
        client_ip: "1.2.3.4".into(),
        reject: None, add_headers: HashMap::new(), remove_headers: vec![],
    };

    plugin.on_request(&mut ctx).unwrap();
    assert_eq!(ctx.reject.unwrap().0, 401);
}

#[test]
fn plugin_header_injector() {
    use volta_gateway::plugin::{Plugin, PluginContext, builtin::HeaderInjector};

    let plugin = HeaderInjector {
        request_headers: {
            let mut h = HashMap::new();
            h.insert("X-Custom".into(), "injected".into());
            h
        },
        response_headers: HashMap::new(),
    };

    let mut ctx = PluginContext {
        method: "GET".into(), host: "test.com".into(), path: "/".into(),
        headers: HashMap::new(), client_ip: "1.2.3.4".into(),
        reject: None, add_headers: HashMap::new(), remove_headers: vec![],
    };

    plugin.on_request(&mut ctx).unwrap();
    assert_eq!(ctx.add_headers.get("X-Custom").unwrap(), "injected");
}

#[test]
fn plugin_manager_loads_from_config() {
    use volta_gateway::plugin::{PluginConfig, PluginManager};

    let configs = vec![
        PluginConfig {
            name: "api-key-auth".into(),
            plugin_type: "native".into(),
            path: None,
            config: {
                let mut c = HashMap::new();
                c.insert("header".into(), "x-api-key".into());
                c.insert("keys".into(), "key1,key2".into());
                c
            },
            phase: "request".into(),
        },
    ];

    let mgr = PluginManager::load_from_config(&configs);
    let states = mgr.states();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].0, "api-key-auth");
    assert!(states[0].1.contains("Active"));
}

// ─── mTLS Config Tests (#9) ────────────────────────────

#[test]
fn mtls_config_parses() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: api.example.com
    backend: https://localhost:3000
    backend_tls:
      ca_cert: /etc/volta/ca.pem
      client_cert: /etc/volta/client.pem
      client_key: /etc/volta/client-key.pem
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());
    let table = config.routing_table();
    let route = table.get("api.example.com").unwrap();
    assert!(route.backend_tls.is_some());
    assert_eq!(route.backend_tls.as_ref().unwrap().ca_cert, "/etc/volta/ca.pem");
}

#[test]
fn cache_config_parses() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: docs.example.com
    backend: http://localhost:3000
    public: true
    cache:
      enabled: true
      ttl_secs: 600
      methods: [GET]
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());
    let table = config.routing_table();
    let route = table.get("docs.example.com").unwrap();
    assert!(route.cache.is_some());
    let cache = route.cache.as_ref().unwrap();
    assert!(cache.enabled);
    assert_eq!(cache.ttl_secs, 600);
}

#[test]
fn plugin_config_parses() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: app.example.com
    backend: http://localhost:3000
plugins:
  - name: api-key-auth
    phase: request
    config:
      header: x-api-key
      keys: "key1,key2"
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.plugins.len(), 1);
    assert_eq!(config.plugins[0].name, "api-key-auth");
}
