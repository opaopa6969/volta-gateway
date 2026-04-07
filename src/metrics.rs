use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// PH2-3: Prometheus-compatible metrics. No external crate — plain text exposition.
///
/// Endpoint: GET /metrics
#[derive(Default)]
pub struct Metrics {
    // Counters
    pub requests_total: AtomicU64,
    pub requests_200: AtomicU64,
    pub requests_302: AtomicU64,
    pub requests_400: AtomicU64,
    pub requests_403: AtomicU64,
    pub requests_429: AtomicU64,
    pub requests_502: AtomicU64,
    pub requests_504: AtomicU64,
    pub rate_limited_total: AtomicU64,

    // SM terminal counters
    pub sm_completed: AtomicU64,
    pub sm_bad_request: AtomicU64,
    pub sm_redirect: AtomicU64,
    pub sm_denied: AtomicU64,
    pub sm_bad_gateway: AtomicU64,
    pub sm_gateway_timeout: AtomicU64,

    // Gauges
    pub active_connections: AtomicU64,

    // Duration tracking (sum of microseconds for average calculation)
    pub request_duration_us_sum: AtomicU64,
    pub auth_duration_us_sum: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_status(&self, status: u16) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        match status {
            200..=299 => { self.requests_200.fetch_add(1, Ordering::Relaxed); }
            302 => { self.requests_302.fetch_add(1, Ordering::Relaxed); }
            400 => { self.requests_400.fetch_add(1, Ordering::Relaxed); }
            403 => { self.requests_403.fetch_add(1, Ordering::Relaxed); }
            429 => { self.requests_429.fetch_add(1, Ordering::Relaxed); }
            502 => { self.requests_502.fetch_add(1, Ordering::Relaxed); }
            504 => { self.requests_504.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    pub fn record_duration(&self, start: Instant) {
        let us = start.elapsed().as_micros() as u64;
        self.request_duration_us_sum.fetch_add(us, Ordering::Relaxed);
    }

    /// Render Prometheus exposition format.
    pub fn render(&self) -> String {
        let total = self.requests_total.load(Ordering::Relaxed);
        let dur_sum = self.request_duration_us_sum.load(Ordering::Relaxed);
        let avg_ms = if total > 0 { dur_sum as f64 / total as f64 / 1000.0 } else { 0.0 };

        format!(
            r#"# HELP volta_gateway_requests_total Total HTTP requests
# TYPE volta_gateway_requests_total counter
volta_gateway_requests_total {{status="2xx"}} {r200}
volta_gateway_requests_total {{status="302"}} {r302}
volta_gateway_requests_total {{status="400"}} {r400}
volta_gateway_requests_total {{status="403"}} {r403}
volta_gateway_requests_total {{status="429"}} {r429}
volta_gateway_requests_total {{status="502"}} {r502}
volta_gateway_requests_total {{status="504"}} {r504}
# HELP volta_gateway_rate_limited_total Rate limited requests
# TYPE volta_gateway_rate_limited_total counter
volta_gateway_rate_limited_total {rl}
# HELP volta_gateway_sm_terminal_total SM terminal state counts
# TYPE volta_gateway_sm_terminal_total counter
volta_gateway_sm_terminal_total {{state="Completed"}} {smc}
volta_gateway_sm_terminal_total {{state="BadRequest"}} {smbr}
volta_gateway_sm_terminal_total {{state="Redirect"}} {smr}
volta_gateway_sm_terminal_total {{state="Denied"}} {smd}
volta_gateway_sm_terminal_total {{state="BadGateway"}} {smbg}
volta_gateway_sm_terminal_total {{state="GatewayTimeout"}} {smgt}
# HELP volta_gateway_active_connections Current active connections
# TYPE volta_gateway_active_connections gauge
volta_gateway_active_connections {ac}
# HELP volta_gateway_request_duration_avg_ms Average request duration (ms)
# TYPE volta_gateway_request_duration_avg_ms gauge
volta_gateway_request_duration_avg_ms {avg:.2}
"#,
            r200 = self.requests_200.load(Ordering::Relaxed),
            r302 = self.requests_302.load(Ordering::Relaxed),
            r400 = self.requests_400.load(Ordering::Relaxed),
            r403 = self.requests_403.load(Ordering::Relaxed),
            r429 = self.requests_429.load(Ordering::Relaxed),
            r502 = self.requests_502.load(Ordering::Relaxed),
            r504 = self.requests_504.load(Ordering::Relaxed),
            rl = self.rate_limited_total.load(Ordering::Relaxed),
            smc = self.sm_completed.load(Ordering::Relaxed),
            smbr = self.sm_bad_request.load(Ordering::Relaxed),
            smr = self.sm_redirect.load(Ordering::Relaxed),
            smd = self.sm_denied.load(Ordering::Relaxed),
            smbg = self.sm_bad_gateway.load(Ordering::Relaxed),
            smgt = self.sm_gateway_timeout.load(Ordering::Relaxed),
            ac = self.active_connections.load(Ordering::Relaxed),
            avg = avg_ms,
        )
    }
}
