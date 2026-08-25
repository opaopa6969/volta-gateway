//! Local-network bypass for `/auth/verify`.
//!
//! Port of Java `LocalNetworkBypass.java` (`5f23f88`, refined in `4006ee7`).
//!
//! When the client IP matches a configured CIDR, `/auth/verify` returns 200
//! without requiring a session — intended for LAN and Tailscale/Headscale
//! access where a VPN or physical-network perimeter already authenticates
//! the caller.
//!
//! Configured via `LOCAL_BYPASS_CIDRS` (comma-separated CIDR list). It is
//! disabled by default. `LOCAL_BYPASS_TRUSTED_PROXY_CIDRS` separately lists
//! the direct peers allowed to supply `X-Real-IP` / `X-Forwarded-For`.
//!
//! Note: ADR `volta-auth-proxy/docs/decisions/002-reject-trusted-network-bypass.md`
//! originally rejected this feature; `5f23f88` reversed that decision in Java
//! but the ADR was never updated. We follow the newer code here and track the
//! discrepancy in `docs/sync-from-java-2026-04-14.md` (Open Decision O1).

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::{request::Parts, HeaderMap};
use ipnet::IpNet;

#[cfg(test)]
const TEST_CIDRS: &str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,127.0.0.1/32";

#[derive(Clone, Debug, Default)]
pub struct LocalNetworkBypass {
    cidrs: Vec<IpNet>,
    trusted_proxies: Vec<IpNet>,
}

/// Optional transport peer extractor. In-process router callers may not have
/// Axum connect info; that is safe because a missing peer can never authorize
/// forwarded headers or trigger local bypass.
pub struct PeerIp(pub Option<IpAddr>);

impl<S> FromRequestParts<S> for PeerIp
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| peer.ip()),
        ))
    }
}

impl LocalNetworkBypass {
    pub fn new(csv: &str) -> Self {
        let mut cidrs = Vec::new();
        for raw in csv.split(',') {
            let s = raw.trim();
            if s.is_empty() {
                continue;
            }
            match s.parse::<IpNet>() {
                Ok(net) => cidrs.push(net),
                Err(_) => {
                    // Accept bare IPs without a `/prefix`, matching Java behaviour.
                    if let Ok(ip) = s.parse::<IpAddr>() {
                        let prefix = if ip.is_ipv4() { 32 } else { 128 };
                        if let Ok(net) = format!("{}/{}", ip, prefix).parse::<IpNet>() {
                            cidrs.push(net);
                            continue;
                        }
                    }
                    tracing::warn!(cidr = s, "invalid LOCAL_BYPASS_CIDRS entry, skipped");
                }
            }
        }
        Self {
            cidrs,
            trusted_proxies: Vec::new(),
        }
    }

    pub fn from_env() -> Self {
        let cidrs = std::env::var("LOCAL_BYPASS_CIDRS").unwrap_or_default();
        let trusted_proxies = std::env::var("LOCAL_BYPASS_TRUSTED_PROXY_CIDRS").unwrap_or_default();
        Self::new(&cidrs).with_trusted_proxies(&trusted_proxies)
    }

    pub fn with_trusted_proxies(mut self, csv: &str) -> Self {
        self.trusted_proxies = Self::new(csv).cidrs;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.cidrs.is_empty()
    }

    /// True when `ip` falls within any configured CIDR.
    pub fn matches(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|net| net.contains(&ip))
    }

    /// Extract the best-effort client IP from forwarded headers and check it
    /// against the configured CIDRs.
    pub fn matches_request(&self, headers: &HeaderMap, peer_ip: Option<IpAddr>) -> bool {
        if self.cidrs.is_empty() {
            return false;
        }
        if let Some(ip) = client_ip(headers, peer_ip, &self.trusted_proxies) {
            return self.matches(ip);
        }
        false
    }
}

/// Resolve the client IP. Forwarding headers are considered only when the
/// transport peer is explicitly trusted; otherwise the direct peer wins.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<IpAddr>,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let peer = peer?;
    if trusted_proxies.iter().any(|net| net.contains(&peer)) {
        for h in ["x-real-ip", "x-forwarded-for"] {
            if let Some(val) = headers.get(h).and_then(|v| v.to_str().ok()) {
                if let Some(first) = val.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }
    }
    Some(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_rfc1918_and_cgnat() {
        let b = LocalNetworkBypass::new(TEST_CIDRS);
        assert!(b.matches("192.168.1.5".parse().unwrap()));
        assert!(b.matches("10.0.0.1".parse().unwrap()));
        assert!(b.matches("172.16.0.1".parse().unwrap()));
        assert!(b.matches("100.64.1.1".parse().unwrap())); // Tailscale CGNAT
        assert!(b.matches("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ip_does_not_match() {
        let b = LocalNetworkBypass::new(TEST_CIDRS);
        assert!(!b.matches("8.8.8.8".parse().unwrap()));
        assert!(!b.matches("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_outside_defaults_ignored() {
        let b = LocalNetworkBypass::new(TEST_CIDRS);
        assert!(!b.matches("::1".parse().unwrap()));
    }

    #[test]
    fn empty_csv_disables_bypass() {
        let b = LocalNetworkBypass::new("");
        assert!(b.is_empty());
        assert!(!b.matches("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn bare_ip_without_prefix_accepted() {
        let b = LocalNetworkBypass::new("203.0.113.7");
        assert!(b.matches("203.0.113.7".parse().unwrap()));
        assert!(!b.matches("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn invalid_entries_skipped() {
        let b = LocalNetworkBypass::new("not-a-cidr, 10.0.0.0/8 , , 192.168.0.0/16");
        assert_eq!(b.cidrs.len(), 2);
        assert!(b.matches("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn trusted_proxy_can_supply_forwarded_header() {
        let b = LocalNetworkBypass::new(TEST_CIDRS).with_trusted_proxies("203.0.113.0/24");
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "10.1.2.3".parse().unwrap());
        assert!(b.matches_request(&h, Some("203.0.113.7".parse().unwrap())));
        let mut h2 = HeaderMap::new();
        h2.insert("x-forwarded-for", "8.8.8.8, 10.1.2.3".parse().unwrap());
        assert!(!b.matches_request(&h2, Some("203.0.113.7".parse().unwrap())));
    }

    #[test]
    fn untrusted_peer_cannot_spoof_local_forwarded_ip() {
        let b = LocalNetworkBypass::new(TEST_CIDRS).with_trusted_proxies("203.0.113.0/24");
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "10.1.2.3".parse().unwrap());
        h.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        assert!(!b.matches_request(&h, Some("198.51.100.9".parse().unwrap())));
    }

    #[test]
    fn missing_peer_never_trusts_forwarded_headers() {
        let b = LocalNetworkBypass::new(TEST_CIDRS).with_trusted_proxies("0.0.0.0/0");
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "10.1.2.3".parse().unwrap());
        assert!(!b.matches_request(&h, None));
    }

    #[test]
    fn matches_request_falls_back_to_peer() {
        let b = LocalNetworkBypass::new(TEST_CIDRS);
        let h = HeaderMap::new();
        assert!(b.matches_request(&h, Some("127.0.0.1".parse().unwrap())));
        assert!(!b.matches_request(&h, Some("8.8.8.8".parse().unwrap())));
    }

    #[tokio::test]
    async fn handler_without_peer_rejects_spoofed_forwarded_ip() {
        use axum::body::Body;
        use axum::extract::State;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use tower::ServiceExt;

        async fn probe(
            State(bypass): State<LocalNetworkBypass>,
            PeerIp(peer): PeerIp,
            headers: HeaderMap,
        ) -> StatusCode {
            if bypass.matches_request(&headers, peer) {
                StatusCode::OK
            } else {
                StatusCode::UNAUTHORIZED
            }
        }

        let app = Router::new()
            .route("/auth/verify", get(probe))
            .with_state(LocalNetworkBypass::new(TEST_CIDRS).with_trusted_proxies("0.0.0.0/0"));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/auth/verify")
                    .header("x-real-ip", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
