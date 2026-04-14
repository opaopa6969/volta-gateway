//! Local-network bypass for `/auth/verify`.
//!
//! Port of Java `LocalNetworkBypass.java` (`5f23f88`, refined in `4006ee7`).
//!
//! When the client IP matches a configured CIDR, `/auth/verify` returns 200
//! without requiring a session — intended for LAN and Tailscale/Headscale
//! access where a VPN or physical-network perimeter already authenticates
//! the caller.
//!
//! Configured via `LOCAL_BYPASS_CIDRS` (comma-separated CIDR list).
//! Default: `192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,127.0.0.1/32`
//! (RFC1918 + Tailscale CGNAT + loopback). Empty value disables bypass.
//!
//! Note: ADR `volta-auth-proxy/docs/decisions/002-reject-trusted-network-bypass.md`
//! originally rejected this feature; `5f23f88` reversed that decision in Java
//! but the ADR was never updated. We follow the newer code here and track the
//! discrepancy in `docs/sync-from-java-2026-04-14.md` (Open Decision O1).

use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

const DEFAULT_CIDRS: &str =
    "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,100.64.0.0/10,127.0.0.1/32";

#[derive(Clone, Debug, Default)]
pub struct LocalNetworkBypass {
    cidrs: Vec<IpNet>,
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
        Self { cidrs }
    }

    pub fn from_env() -> Self {
        let csv = std::env::var("LOCAL_BYPASS_CIDRS").unwrap_or_else(|_| DEFAULT_CIDRS.into());
        Self::new(&csv)
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
        if let Some(ip) = client_ip(headers, peer_ip) {
            return self.matches(ip);
        }
        false
    }
}

/// Resolve the client IP: prefer `X-Real-IP` / `X-Forwarded-For` (gateway fills
/// these), fall back to the direct peer.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>) -> Option<IpAddr> {
    for h in ["x-real-ip", "x-forwarded-for"] {
        if let Some(val) = headers.get(h).and_then(|v| v.to_str().ok()) {
            if let Some(first) = val.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_rfc1918_and_cgnat() {
        let b = LocalNetworkBypass::new(DEFAULT_CIDRS);
        assert!(b.matches("192.168.1.5".parse().unwrap()));
        assert!(b.matches("10.0.0.1".parse().unwrap()));
        assert!(b.matches("172.16.0.1".parse().unwrap()));
        assert!(b.matches("100.64.1.1".parse().unwrap())); // Tailscale CGNAT
        assert!(b.matches("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn public_ip_does_not_match() {
        let b = LocalNetworkBypass::new(DEFAULT_CIDRS);
        assert!(!b.matches("8.8.8.8".parse().unwrap()));
        assert!(!b.matches("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_outside_defaults_ignored() {
        let b = LocalNetworkBypass::new(DEFAULT_CIDRS);
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
    fn matches_request_uses_forwarded_header() {
        let b = LocalNetworkBypass::new(DEFAULT_CIDRS);
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "10.1.2.3".parse().unwrap());
        assert!(b.matches_request(&h, None));
        let mut h2 = HeaderMap::new();
        h2.insert("x-forwarded-for", "8.8.8.8, 10.1.2.3".parse().unwrap());
        assert!(!b.matches_request(&h2, None));
    }

    #[test]
    fn matches_request_falls_back_to_peer() {
        let b = LocalNetworkBypass::new(DEFAULT_CIDRS);
        let h = HeaderMap::new();
        assert!(b.matches_request(&h, Some("127.0.0.1".parse().unwrap())));
        assert!(!b.matches_request(&h, Some("8.8.8.8".parse().unwrap())));
    }
}
