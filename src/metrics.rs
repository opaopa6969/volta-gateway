use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// PH2-3: Prometheus-compatible metrics. No external crate — plain text exposition.
///
/// Endpoint: GET /metrics
#[derive(Default)]
#[allow(dead_code)]
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

    // GW-27: WebSocket metrics
    pub ws_connections_total: AtomicU64,
    pub ws_active: AtomicU64,
    pub ws_rejected_limit: AtomicU64,

    // GW-27: Circuit breaker metrics
    pub cb_opens_total: AtomicU64,
    pub cb_half_opens_total: AtomicU64,
    pub cb_resets_total: AtomicU64,

    // GW-27: Compression metrics
    pub compression_applied_total: AtomicU64,
    pub compression_skipped_total: AtomicU64,
    pub compression_bytes_saved: AtomicU64,

    // GW-27: L4 proxy metrics
    pub l4_tcp_connections_total: AtomicU64,
    pub l4_tcp_active: AtomicU64,
    pub l4_udp_packets_total: AtomicU64,

    // PROD-5: Latency histogram buckets (μs thresholds)
    // Buckets: ≤1ms, ≤5ms, ≤25ms, ≤100ms, ≤500ms, ≤1s, ≤5s, >5s
    pub latency_bucket_1ms: AtomicU64,
    pub latency_bucket_5ms: AtomicU64,
    pub latency_bucket_25ms: AtomicU64,
    pub latency_bucket_100ms: AtomicU64,
    pub latency_bucket_500ms: AtomicU64,
    pub latency_bucket_1s: AtomicU64,
    pub latency_bucket_5s: AtomicU64,
    pub latency_bucket_inf: AtomicU64,
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

        // PROD-5: Histogram bucket
        let ms = us / 1000;
        match ms {
            0..=1 => self.latency_bucket_1ms.fetch_add(1, Ordering::Relaxed),
            2..=5 => self.latency_bucket_5ms.fetch_add(1, Ordering::Relaxed),
            6..=25 => self.latency_bucket_25ms.fetch_add(1, Ordering::Relaxed),
            26..=100 => self.latency_bucket_100ms.fetch_add(1, Ordering::Relaxed),
            101..=500 => self.latency_bucket_500ms.fetch_add(1, Ordering::Relaxed),
            501..=1000 => self.latency_bucket_1s.fetch_add(1, Ordering::Relaxed),
            1001..=5000 => self.latency_bucket_5s.fetch_add(1, Ordering::Relaxed),
            _ => self.latency_bucket_inf.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Render Prometheus exposition format.
    pub fn render(&self) -> String {
        let total = self.requests_total.load(Ordering::Relaxed);
        let dur_sum = self.request_duration_us_sum.load(Ordering::Relaxed);
        let avg_ms = if total > 0 { dur_sum as f64 / total as f64 / 1000.0 } else { 0.0 };

        // Histogram bucket loads
        let b1 = self.latency_bucket_1ms.load(Ordering::Relaxed);
        let b5 = self.latency_bucket_5ms.load(Ordering::Relaxed);
        let b25 = self.latency_bucket_25ms.load(Ordering::Relaxed);
        let b100 = self.latency_bucket_100ms.load(Ordering::Relaxed);
        let b500 = self.latency_bucket_500ms.load(Ordering::Relaxed);
        let b1000 = self.latency_bucket_1s.load(Ordering::Relaxed);
        let b5000 = self.latency_bucket_5s.load(Ordering::Relaxed);
        let binf = self.latency_bucket_inf.load(Ordering::Relaxed);

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
# HELP volta_gateway_ws_connections_total Total WebSocket connections
# TYPE volta_gateway_ws_connections_total counter
volta_gateway_ws_connections_total {ws_total}
# HELP volta_gateway_ws_active Active WebSocket tunnels
# TYPE volta_gateway_ws_active gauge
volta_gateway_ws_active {ws_active}
# HELP volta_gateway_ws_rejected_limit WebSocket connections rejected (limit)
# TYPE volta_gateway_ws_rejected_limit counter
volta_gateway_ws_rejected_limit {ws_rej}
# HELP volta_gateway_circuit_breaker_opens_total Circuit breaker open events
# TYPE volta_gateway_circuit_breaker_opens_total counter
volta_gateway_circuit_breaker_opens_total {cb_open}
# HELP volta_gateway_circuit_breaker_resets_total Circuit breaker reset events
# TYPE volta_gateway_circuit_breaker_resets_total counter
volta_gateway_circuit_breaker_resets_total {cb_reset}
# HELP volta_gateway_compression_applied_total Responses compressed
# TYPE volta_gateway_compression_applied_total counter
volta_gateway_compression_applied_total {comp_applied}
# HELP volta_gateway_compression_skipped_total Responses not compressed
# TYPE volta_gateway_compression_skipped_total counter
volta_gateway_compression_skipped_total {comp_skip}
# HELP volta_gateway_compression_bytes_saved_total Bytes saved by compression
# TYPE volta_gateway_compression_bytes_saved_total counter
volta_gateway_compression_bytes_saved_total {comp_saved}
# HELP volta_gateway_l4_tcp_connections_total L4 TCP connections total
# TYPE volta_gateway_l4_tcp_connections_total counter
volta_gateway_l4_tcp_connections_total {l4_tcp}
# HELP volta_gateway_l4_tcp_active L4 TCP active connections
# TYPE volta_gateway_l4_tcp_active gauge
volta_gateway_l4_tcp_active {l4_tcp_active}
# HELP volta_gateway_l4_udp_packets_total L4 UDP packets forwarded
# TYPE volta_gateway_l4_udp_packets_total counter
volta_gateway_l4_udp_packets_total {l4_udp}
# HELP volta_gateway_request_duration_ms Latency histogram
# TYPE volta_gateway_request_duration_ms histogram
volta_gateway_request_duration_ms_bucket{{le="1"}} {h1}
volta_gateway_request_duration_ms_bucket{{le="5"}} {h5}
volta_gateway_request_duration_ms_bucket{{le="25"}} {h25}
volta_gateway_request_duration_ms_bucket{{le="100"}} {h100}
volta_gateway_request_duration_ms_bucket{{le="500"}} {h500}
volta_gateway_request_duration_ms_bucket{{le="1000"}} {h1000}
volta_gateway_request_duration_ms_bucket{{le="5000"}} {h5000}
volta_gateway_request_duration_ms_bucket{{le="+Inf"}} {hinf}
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
            ws_total = self.ws_connections_total.load(Ordering::Relaxed),
            ws_active = self.ws_active.load(Ordering::Relaxed),
            ws_rej = self.ws_rejected_limit.load(Ordering::Relaxed),
            cb_open = self.cb_opens_total.load(Ordering::Relaxed),
            cb_reset = self.cb_resets_total.load(Ordering::Relaxed),
            comp_applied = self.compression_applied_total.load(Ordering::Relaxed),
            comp_skip = self.compression_skipped_total.load(Ordering::Relaxed),
            comp_saved = self.compression_bytes_saved.load(Ordering::Relaxed),
            l4_tcp = self.l4_tcp_connections_total.load(Ordering::Relaxed),
            l4_tcp_active = self.l4_tcp_active.load(Ordering::Relaxed),
            l4_udp = self.l4_udp_packets_total.load(Ordering::Relaxed),
            // PROD-5: Cumulative histogram buckets
            h1 = b1,
            h5 = b1 + b5,
            h25 = b1 + b5 + b25,
            h100 = b1 + b5 + b25 + b100,
            h500 = b1 + b5 + b25 + b100 + b500,
            h1000 = b1 + b5 + b25 + b100 + b500 + b1000,
            h5000 = b1 + b5 + b25 + b100 + b500 + b1000 + b5000,
            hinf = b1 + b5 + b25 + b100 + b500 + b1000 + b5000 + binf,
        )
    }
}
