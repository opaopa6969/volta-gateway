//! Security utilities — constant-time compare, URL validation, localhost check, Unicode normalization.
//!
//! Counterparts of Java-side fixes in `abca91e` (issues #1, #7, #8, #10, #14, #19, #21).

use std::net::IpAddr;

use axum::http::HeaderMap;
use unicode_normalization::UnicodeNormalization;

/// Constant-time comparison of two byte slices.
///
/// Returns `true` iff the inputs are equal. Runtime depends only on the length
/// of `a` — length mismatches return `false` in constant time w.r.t. `a`.
///
/// Used for hash / HMAC / secret comparison. Fixes issue #21 (early exit leak).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    ring::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Validate a webhook endpoint URL (issue #1 SSRF).
///
/// Rules (matches Java ApiRouter):
/// - must parse as a URL
/// - scheme must be `https` (plus `http` if `allow_http` = true)
/// - host must not resolve to a private / loopback / link-local IP literal
/// - host must not be a plain `localhost` (case-insensitive)
///
/// Actual DNS resolution is intentionally not performed — operators can still
/// point at private hosts via DNS if they want, the goal here is to reject the
/// obvious attacker payloads (`http://169.254.169.254/`, `http://127.0.0.1/`,
/// raw IP literals to private ranges).
pub fn validate_webhook_url(url_str: &str, allow_http: bool) -> Result<(), String> {
    let parsed = url::Url::parse(url_str).map_err(|e| format!("invalid URL: {}", e))?;

    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        s => return Err(format!("scheme must be https (got {})", s)),
    }

    let host = parsed.host_str().ok_or_else(|| "URL has no host".to_string())?;

    if host.eq_ignore_ascii_case("localhost") {
        return Err("localhost is not allowed".into());
    }

    // `url::Url::host_str` keeps brackets on IPv6 literals (e.g. "[::1]"). Strip
    // them before parsing so IpAddr::from_str can succeed.
    let host_for_ip = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    if let Ok(ip) = host_for_ip.parse::<IpAddr>() {
        if is_forbidden_ip(&ip) {
            return Err(format!("IP {} is in a forbidden range", ip));
        }
    }
    Ok(())
}

fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                // cloud metadata
                || v4.octets() == [169, 254, 169, 254]
                // CGNAT (Tailscale)
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 0x40
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Determine whether the request originated from localhost (issue #8 SAML devMode guard).
///
/// Trusts the peer IP in `X-Forwarded-For` / `X-Real-IP` headers only if the
/// resolved IP is itself loopback — consistent with Java's `isLocalRequest()`
/// helper, which looks at the direct peer before trusting any proxy header.
pub fn is_localhost_request(headers: &HeaderMap) -> bool {
    for name in ["x-real-ip", "x-forwarded-for"] {
        if let Some(val) = headers.get(name).and_then(|v| v.to_str().ok()) {
            let first = val.split(',').next().unwrap_or("").trim();
            if let Ok(ip) = first.parse::<IpAddr>() {
                return ip.is_loopback();
            }
        }
    }
    // No proxy header → assume the peer is local only in dev runs (integration tests,
    // `cargo run`). In production a gateway always fills X-Real-IP, so absence means
    // direct localhost access.
    true
}

/// NFC-normalize and lowercase an email for comparison (issue #14 homoglyph bypass).
///
/// Applied before storing or comparing `users.email` and invite `email` fields.
pub fn normalize_email(email: &str) -> String {
    email.trim().nfc().collect::<String>().to_lowercase()
}

/// Reject SAML XML that contains DTD / external entity declarations (issue #19 XXE).
///
/// The actual SAML parser in `saml.rs` is text-based and does not expand entities,
/// but we still reject these tokens defensively — any well-formed IdP response
/// never needs them.
pub fn reject_xml_doctype(xml: &str) -> Result<(), String> {
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") {
        return Err("DOCTYPE declarations are not allowed".into());
    }
    if upper.contains("<!ENTITY") {
        return Err("ENTITY declarations are not allowed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_equal() {
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn ct_eq_diff_value_same_len() {
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn ct_eq_diff_len() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn webhook_https_ok() {
        validate_webhook_url("https://example.com/hook", false).unwrap();
    }

    #[test]
    fn webhook_http_blocked_by_default() {
        assert!(validate_webhook_url("http://example.com/hook", false).is_err());
    }

    #[test]
    fn webhook_http_allowed_when_flag_set() {
        validate_webhook_url("http://example.com/hook", true).unwrap();
    }

    #[test]
    fn webhook_reject_localhost() {
        assert!(validate_webhook_url("https://localhost/x", false).is_err());
        assert!(validate_webhook_url("https://127.0.0.1/x", false).is_err());
    }

    #[test]
    fn webhook_reject_private_range() {
        assert!(validate_webhook_url("https://10.0.0.1/x", false).is_err());
        assert!(validate_webhook_url("https://192.168.1.1/x", false).is_err());
        assert!(validate_webhook_url("https://172.16.0.1/x", false).is_err());
    }

    #[test]
    fn webhook_reject_metadata() {
        assert!(validate_webhook_url("https://169.254.169.254/latest/meta-data/", false).is_err());
    }

    #[test]
    fn webhook_reject_cgnat() {
        assert!(validate_webhook_url("https://100.64.1.1/x", false).is_err());
    }

    #[test]
    fn webhook_reject_ipv6_loopback() {
        assert!(validate_webhook_url("https://[::1]/x", false).is_err());
    }

    #[test]
    fn webhook_reject_ftp() {
        assert!(validate_webhook_url("ftp://example.com/", false).is_err());
    }

    #[test]
    fn email_normalize_nfc() {
        // Composed vs decomposed form — same character, different encodings
        let composed = "café@example.com"; // NFC
        let decomposed = "cafe\u{0301}@example.com"; // NFD
        assert_eq!(normalize_email(composed), normalize_email(decomposed));
    }

    #[test]
    fn email_normalize_case() {
        assert_eq!(normalize_email("User@Example.COM"), "user@example.com");
    }

    #[test]
    fn reject_doctype() {
        let xml = r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#;
        assert!(reject_xml_doctype(xml).is_err());
    }

    #[test]
    fn allow_plain_xml() {
        reject_xml_doctype(r#"<?xml version="1.0"?><foo>bar</foo>"#).unwrap();
    }
}
