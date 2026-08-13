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

    /// 環境変数で上書きできる `new`。
    ///
    /// 上限がコード埋め込みだと、環境ごとに合わないときに再ビルドするしかない。
    /// 実際 oidc と passkey は「5/min では正規ユーザーがロックアウトされる」と
    /// 分かって 30 に上げ直している。E2E も magic-link の 5/min に当たって
    /// 通らなかった。`LOCAL_BYPASS_CIDRS` と同じく env で調整できるようにする。
    ///
    /// 優先順位:
    ///   1. `RATE_LIMIT_<NAME>`  — この limiter だけを上書き（例 `RATE_LIMIT_MAGIC_LINK=100`）
    ///   2. `RATE_LIMIT_MULTIPLIER` — 全 limiter の既定値に掛ける倍率（例 `10`）
    ///   3. 引数の `default_limit`
    ///
    /// `<NAME>` は limiter 名を大文字にしてハイフンを `_` にしたもの
    /// （`magic-link` → `RATE_LIMIT_MAGIC_LINK`）。
    ///
    /// **`0` を渡すとその limiter は無効**になる（無制限）。テスト環境向け。
    /// 本番で 0 にすると総当たりを止められなくなるので注意。
    ///
    /// 窓幅は `RATE_LIMIT_WINDOW_SECS` で全体を変えられる（既定は引数のまま）。
    pub fn from_env(name: &'static str, default_limit: u32, default_window: Duration) -> Self {
        let key = format!("RATE_LIMIT_{}", name.to_uppercase().replace('-', "_"));

        let limit = std::env::var(&key)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or_else(|| {
                let mult = std::env::var("RATE_LIMIT_MULTIPLIER")
                    .ok()
                    .and_then(|v| v.trim().parse::<f64>().ok())
                    .filter(|m| *m > 0.0)
                    .unwrap_or(1.0);
                // 倍率で 0 に落ちると意図せず無効化されるので、下限を 1 にする。
                // 無効化したいときは RATE_LIMIT_<NAME>=0 と明示すること。
                (((default_limit as f64) * mult).round() as u32).max(1)
            });

        let window = std::env::var("RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|s| *s > 0)
            .map(Duration::from_secs)
            .unwrap_or(default_window);

        Self::new(name, limit, window)
    }

    /// この limiter が無効化されているか（`limit == 0`）。
    pub fn is_disabled(&self) -> bool {
        self.limit == 0
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// `true` when the request is *allowed*, `false` when it should be rejected.
    ///
    /// #20: compare with `<`, not `<=`, so `limit` requests succeed per window
    /// and the `limit + 1`-th is rejected — matches the Java fix.
    pub fn check(&self, key: &str) -> bool {
        // limit 0 = 無効。バケットも作らない（無制限なら数える意味が無く、
        // キーごとにメモリを食うだけになる）。
        if self.limit == 0 {
            return true;
        }
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
    fn zero_limit_disables_the_limiter() {
        // テスト環境で `RATE_LIMIT_<NAME>=0` を指定したときの挙動。
        let rl = RateLimiter::new("test", 0, Duration::from_secs(60));
        assert!(rl.is_disabled());
        for _ in 0..1000 {
            assert!(rl.check("k"));
        }
    }

    // env を読むテストはプロセス全体の環境変数を触るので、並行実行されると
    // 互いに干渉する。1つのテストに直列でまとめる。
    #[test]
    fn from_env_overrides() {
        // 何も設定しなければ既定値
        std::env::remove_var("RATE_LIMIT_MAGIC_LINK");
        std::env::remove_var("RATE_LIMIT_MULTIPLIER");
        std::env::remove_var("RATE_LIMIT_WINDOW_SECS");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.limit(), 5);
        assert_eq!(rl.window, Duration::from_secs(60));

        // 個別上書き。ハイフンは `_` に、大文字に正規化される
        std::env::set_var("RATE_LIMIT_MAGIC_LINK", "100");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.limit(), 100);

        // 0 は無効化。個別指定でのみ到達できる
        std::env::set_var("RATE_LIMIT_MAGIC_LINK", "0");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert!(rl.is_disabled());
        std::env::remove_var("RATE_LIMIT_MAGIC_LINK");

        // 倍率は全 limiter の既定値に掛かる
        std::env::set_var("RATE_LIMIT_MULTIPLIER", "10");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.limit(), 50);

        // 倍率で 0 に落ちても無効化はしない（意図しない無制限を防ぐ）
        std::env::set_var("RATE_LIMIT_MULTIPLIER", "0.01");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.limit(), 1);
        assert!(!rl.is_disabled());

        // 個別指定は倍率より優先される
        std::env::set_var("RATE_LIMIT_MULTIPLIER", "10");
        std::env::set_var("RATE_LIMIT_MAGIC_LINK", "7");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.limit(), 7);

        // 壊れた値は無視して既定に落ちる
        std::env::remove_var("RATE_LIMIT_MULTIPLIER");
        std::env::set_var("RATE_LIMIT_MAGIC_LINK", "abc");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.limit(), 5);

        // 窓幅は全体で変えられる
        std::env::remove_var("RATE_LIMIT_MAGIC_LINK");
        std::env::set_var("RATE_LIMIT_WINDOW_SECS", "5");
        let rl = RateLimiter::from_env("magic-link", 5, Duration::from_secs(60));
        assert_eq!(rl.window, Duration::from_secs(5));

        std::env::remove_var("RATE_LIMIT_WINDOW_SECS");
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
