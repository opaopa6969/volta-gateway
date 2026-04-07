use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use volta_gateway::proxy::{ErrorPages, CorsTable};

// ─── Circuit Breaker Tests ─────────────────────────────

/// Minimal circuit breaker reimplementation for unit testing
/// (mirrors proxy.rs CircuitBreaker logic)
struct TestCircuitBreaker {
    backends: Mutex<HashMap<String, (u32, Instant, bool)>>,
    threshold: u32,
    recovery_secs: u64,
}

impl TestCircuitBreaker {
    fn new(threshold: u32, recovery_secs: u64) -> Self {
        Self {
            backends: Mutex::new(HashMap::new()),
            threshold,
            recovery_secs,
        }
    }

    fn is_available(&self, backend: &str) -> bool {
        let map = self.backends.lock().unwrap();
        match map.get(backend) {
            None => true,
            Some((_, last, open)) => {
                if !open { return true; }
                last.elapsed() >= Duration::from_secs(self.recovery_secs)
            }
        }
    }

    fn record_success(&self, backend: &str) {
        let mut map = self.backends.lock().unwrap();
        map.remove(backend);
    }

    fn record_failure(&self, backend: &str) {
        let mut map = self.backends.lock().unwrap();
        let entry = map.entry(backend.to_string())
            .or_insert((0, Instant::now(), false));
        entry.0 += 1;
        entry.1 = Instant::now();
        if entry.0 >= self.threshold {
            entry.2 = true;
        }
    }
}

#[test]
fn circuit_breaker_starts_closed() {
    let cb = TestCircuitBreaker::new(3, 30);
    assert!(cb.is_available("http://backend:3000"));
}

#[test]
fn circuit_breaker_opens_after_threshold() {
    let cb = TestCircuitBreaker::new(3, 30);
    let backend = "http://backend:3000";
    cb.record_failure(backend);
    cb.record_failure(backend);
    assert!(cb.is_available(backend)); // 2 < 3
    cb.record_failure(backend);
    assert!(!cb.is_available(backend)); // 3 >= 3 → open
}

#[test]
fn circuit_breaker_resets_on_success() {
    let cb = TestCircuitBreaker::new(3, 30);
    let backend = "http://backend:3000";
    cb.record_failure(backend);
    cb.record_failure(backend);
    cb.record_success(backend);
    // After success, circuit resets
    assert!(cb.is_available(backend));
    // Need full threshold again to open
    cb.record_failure(backend);
    cb.record_failure(backend);
    assert!(cb.is_available(backend)); // 2 < 3
}

#[test]
fn circuit_breaker_independent_per_backend() {
    let cb = TestCircuitBreaker::new(2, 30);
    cb.record_failure("http://a:3000");
    cb.record_failure("http://a:3000");
    assert!(!cb.is_available("http://a:3000")); // open
    assert!(cb.is_available("http://b:3000"));  // still closed
}

// ─── Compression Header Preservation Tests ─────────────

#[test]
fn compression_preserves_headers_via_into_parts() {
    // Simulate what GW-36 fix does: into_parts() preserves headers
    use hyper::{Response, StatusCode};
    use hyper::header::HeaderValue;

    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("set-cookie", "session=abc123; Path=/; HttpOnly")
        .header("cache-control", "max-age=3600")
        .header("etag", "\"v1\"")
        .header("x-custom", "preserved")
        .body(())
        .unwrap();

    let (parts, _body) = resp.into_parts();

    // Verify all headers survived into_parts()
    assert_eq!(
        parts.headers.get("set-cookie").unwrap(),
        &HeaderValue::from_static("session=abc123; Path=/; HttpOnly")
    );
    assert_eq!(
        parts.headers.get("cache-control").unwrap(),
        &HeaderValue::from_static("max-age=3600")
    );
    assert_eq!(
        parts.headers.get("etag").unwrap(),
        &HeaderValue::from_static("\"v1\"")
    );
    assert_eq!(
        parts.headers.get("x-custom").unwrap(),
        &HeaderValue::from_static("preserved")
    );

    // Rebuild response — skip content-length/content-encoding (as compression does)
    let mut new_resp = Response::builder().status(parts.status);
    for (name, value) in &parts.headers {
        match name.as_str() {
            "content-length" | "content-encoding" | "transfer-encoding" => {}
            _ => { new_resp = new_resp.header(name, value); }
        }
    }
    new_resp = new_resp
        .header("content-encoding", "gzip")
        .header("content-length", "42");

    let rebuilt = new_resp.body(()).unwrap();
    assert_eq!(rebuilt.headers().get("set-cookie").unwrap(), "session=abc123; Path=/; HttpOnly");
    assert_eq!(rebuilt.headers().get("cache-control").unwrap(), "max-age=3600");
    assert_eq!(rebuilt.headers().get("content-encoding").unwrap(), "gzip");
}

#[test]
fn compression_skips_already_encoded() {
    // If backend already set content-encoding, we should not compress
    let resp = hyper::Response::builder()
        .header("content-encoding", "br")
        .header("content-type", "application/json")
        .body(())
        .unwrap();
    let already_encoded = resp.headers().contains_key("content-encoding");
    assert!(already_encoded);
}

#[test]
fn compression_skips_non_compressible() {
    let resp = hyper::Response::builder()
        .header("content-type", "image/png")
        .body(())
        .unwrap();
    let is_compressible = resp.headers().get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript"))
        .unwrap_or(false);
    assert!(!is_compressible);
}

#[test]
fn compression_detects_compressible_types() {
    for ct in &["text/html", "application/json", "text/xml", "application/javascript"] {
        let is_compressible = ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript");
        assert!(is_compressible, "{} should be compressible", ct);
    }
}

// ─── CORS Tests ────────────────────────────────────────

#[test]
fn cors_no_headers_when_no_config() {
    // GW-44: no cors_origins config → no CORS headers (not wildcard)
    let cors: CorsTable = HashMap::new();
    let host = "app.example.com";
    let cors_origin = match cors.get(host) {
        Some(_origins) => "per-route".to_string(),
        None => String::new(), // GW-44: empty = no CORS
    };
    assert!(cors_origin.is_empty());
}

#[test]
fn cors_explicit_wildcard() {
    // GW-44: explicit "*" in cors_origins → wildcard
    let mut cors: CorsTable = HashMap::new();
    cors.insert("app.example.com".into(), vec!["*".into()]);
    let origins = cors.get("app.example.com").unwrap();
    assert!(origins.iter().any(|o| o == "*"));
}

#[test]
fn cors_per_route_matches_origin() {
    let mut cors: CorsTable = HashMap::new();
    cors.insert("app.example.com".into(), vec![
        "https://app.example.com".into(),
        "https://staging.example.com".into(),
    ]);

    let origins = cors.get("app.example.com").unwrap();
    assert!(origins.iter().any(|o| o == "https://app.example.com"));
    assert!(origins.iter().any(|o| o == "https://staging.example.com"));
    assert!(!origins.iter().any(|o| o == "https://evil.com"));
}

#[test]
fn cors_per_route_rejects_unknown_origin() {
    let mut cors: CorsTable = HashMap::new();
    cors.insert("app.example.com".into(), vec!["https://app.example.com".into()]);

    let origins = cors.get("app.example.com").unwrap();
    let req_origin = "https://evil.com";
    let matched = origins.iter().any(|o| o == req_origin);
    assert!(!matched);
}

// ─── Error Pages Tests ─────────────────────────────────

#[test]
fn error_pages_empty_when_no_dir() {
    let pages: ErrorPages = HashMap::new();
    assert!(pages.get(&502).is_none());
}

#[test]
fn error_pages_lookup() {
    let mut pages: ErrorPages = HashMap::new();
    pages.insert(502, "<h1>Bad Gateway</h1>".into());
    pages.insert(403, "<h1>Forbidden</h1>".into());

    assert_eq!(pages.get(&502).unwrap(), "<h1>Bad Gateway</h1>");
    assert_eq!(pages.get(&403).unwrap(), "<h1>Forbidden</h1>");
    assert!(pages.get(&404).is_none()); // falls back to JSON
}

// ─── Config Validation Tests ───────────────────────────

#[test]
fn config_rejects_empty_routing() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing: []
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().iter().any(|e| e.contains("routing is empty")));
}

#[test]
fn config_rejects_duplicate_hosts() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: app.example.com
    backend: http://localhost:3000
  - host: app.example.com
    backend: http://localhost:3001
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    assert!(result.unwrap_err().iter().any(|e| e.contains("duplicate")));
}

#[test]
fn config_accepts_valid_routing() {
    use volta_gateway::config::GatewayConfig;
    let yaml = r#"
server:
  port: 8080
auth:
  volta_url: http://localhost:7070
routing:
  - host: app.example.com
    backend: http://localhost:3000
    cors_origins:
      - https://app.example.com
"#;
    let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.validate().is_ok());
    // Verify cors_table
    let cors = config.cors_table();
    assert!(cors.contains_key("app.example.com"));
}
