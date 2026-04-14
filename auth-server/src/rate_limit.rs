//! Per-endpoint rate limiter (#7, #10, #20).
//!
//! Simple fixed-window limiter keyed by client IP. Each limiter instance holds
//! an in-memory map of `key → (window_start, count)`. The counter resets when
//! the window rolls over.
//!
//! Java counterpart: `RateLimiter.java` in volta-auth-proxy. The Java version
//! had the classic off-by-one (`count <= limit`) bug; we encode `count < limit`
//! here so the `N`-th request past the threshold is the one that gets 429,
//! not the `N+1`-th (#20).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Inner>>,
    limit: u32,
    window: Duration,
    name: &'static str,
}

struct Inner {
    buckets: HashMap<String, (Instant, u32)>,
}

impl RateLimiter {
    pub fn new(name: &'static str, limit: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner { buckets: HashMap::new() })),
            limit,
            window,
            name,
        }
    }

    /// `true` when the request is *allowed*, `false` when it should be rejected.
    ///
    /// #20: compare with `<`, not `<=`, so `limit` requests succeed per window
    /// and the `limit + 1`-th is rejected — matches the Java fix.
    pub fn check(&self, key: &str) -> bool {
        let mut g = self.inner.lock().expect("rate limiter poisoned");
        let now = Instant::now();
        let entry = g.buckets.entry(key.to_string()).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        if entry.1 < self.limit {
            entry.1 += 1;
            true
        } else {
            false
        }
    }

    /// Reap buckets that haven't rolled over recently. Called occasionally by
    /// callers — cheap enough to run per-request for small deployments, but we
    /// leave scheduling to the caller.
    pub fn gc(&self) {
        let mut g = self.inner.lock().expect("rate limiter poisoned");
        let now = Instant::now();
        g.buckets.retain(|_, (start, _)| now.duration_since(*start) < self.window * 2);
    }
}

/// Extract the client IP from either `ConnectInfo` (direct peer) or the
/// gateway's forwarded header. Returns a stringified IP.
pub fn client_ip_key(headers: &HeaderMap, peer: &ConnectInfo<std::net::SocketAddr>) -> String {
    for h in ["x-real-ip", "x-forwarded-for"] {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
            let first = v.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                if let Ok(ip) = first.parse::<IpAddr>() {
                    return ip.to_string();
                }
            }
        }
    }
    peer.0.ip().to_string()
}

/// Axum middleware that enforces a limiter keyed by client IP.
pub async fn limit_by_ip(
    State(limiter): State<RateLimiter>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let key = client_ip_key(req.headers(), &ConnectInfo(peer));
    if !limiter.check(&key) {
        tracing::warn!(limiter = limiter.name, key = %key, "rate limit hit");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "60")],
            format!(r#"{{"error":"RATE_LIMITED","limiter":"{}"}}"#, limiter.name),
        )
            .into_response();
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_limit_passes() {
        let rl = RateLimiter::new("test", 3, Duration::from_secs(60));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
    }

    #[test]
    fn at_limit_rejects() {
        // #20: exactly `limit` requests succeed; request number `limit + 1` fails.
        let rl = RateLimiter::new("test", 3, Duration::from_secs(60));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
    }

    #[test]
    fn different_keys_are_independent() {
        let rl = RateLimiter::new("test", 1, Duration::from_secs(60));
        assert!(rl.check("a"));
        assert!(!rl.check("a"));
        assert!(rl.check("b"));
    }

    #[test]
    fn window_rollover_resets() {
        let rl = RateLimiter::new("test", 1, Duration::from_millis(50));
        assert!(rl.check("k"));
        assert!(!rl.check("k"));
        std::thread::sleep(Duration::from_millis(60));
        assert!(rl.check("k"));
    }
}
