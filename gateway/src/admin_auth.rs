//! BT-SEC-7: Admin API authentication decision.
//!
//! The actual `/admin/*` request handling lives in `main.rs` (inside the hyper
//! connection loop), but the auth *decision* is factored out here so it can be
//! unit-tested independently of the HTTP machinery.
//!
//! Policy:
//! - When a token is configured (YAML `admin.token` or env `VOLTA_ADMIN_TOKEN`),
//!   every `/admin/*` request must present a matching
//!   `Authorization: Bearer <token>` header (read and write alike).
//!   Mismatch/missing → 401.
//! - When no token is configured, the admin API stays loopback-only (enforced
//!   separately) and all *mutating* (non-GET) endpoints are rejected with 403.

/// Outcome of an admin auth check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuth {
    /// Request is authorized — proceed to the handler.
    Allow,
    /// Token configured but the Bearer token was missing or wrong → 401.
    Unauthorized,
    /// No token configured and the request is mutating → 403.
    WriteDisabled,
}

/// Decide whether an `/admin/*` request may proceed.
///
/// - `expected_token`: the effective admin token (`None` if unset).
/// - `auth_header`: the raw `Authorization` header value, if present.
/// - `is_mutating`: `true` for any non-GET method (POST/PATCH/DELETE/PUT…).
///
/// Loopback enforcement is handled by the caller and is orthogonal to this.
pub fn decide(
    expected_token: Option<&str>,
    auth_header: Option<&str>,
    is_mutating: bool,
) -> AdminAuth {
    match expected_token {
        Some(expected) => {
            let provided = auth_header.and_then(|v| v.strip_prefix("Bearer "));
            match provided {
                Some(tok) if constant_time_eq(tok.as_bytes(), expected.as_bytes()) => {
                    AdminAuth::Allow
                }
                _ => AdminAuth::Unauthorized,
            }
        }
        None => {
            if is_mutating {
                AdminAuth::WriteDisabled
            } else {
                AdminAuth::Allow
            }
        }
    }
}

/// Constant-time byte-slice comparison via `subtle::ConstantTimeEq`, to avoid
/// leaking the token through response timing. `ct_eq` itself is constant-time
/// for equal-length inputs; the early length check below is not secret-dependent
/// beyond revealing length, which is acceptable here.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "s3cr3t-admin-token";

    // ── Token configured ─────────────────────────────────────────

    #[test]
    fn matching_bearer_token_allows_read() {
        let hdr = format!("Bearer {}", TOKEN);
        assert_eq!(
            decide(Some(TOKEN), Some(&hdr), false),
            AdminAuth::Allow,
            "matching token on a GET must be allowed",
        );
    }

    #[test]
    fn matching_bearer_token_allows_write() {
        let hdr = format!("Bearer {}", TOKEN);
        assert_eq!(
            decide(Some(TOKEN), Some(&hdr), true),
            AdminAuth::Allow,
            "matching token on a mutating request must be allowed",
        );
    }

    #[test]
    fn wrong_token_is_unauthorized() {
        assert_eq!(
            decide(Some(TOKEN), Some("Bearer wrong-token"), false),
            AdminAuth::Unauthorized,
        );
    }

    #[test]
    fn missing_auth_header_is_unauthorized() {
        assert_eq!(
            decide(Some(TOKEN), None, false),
            AdminAuth::Unauthorized,
        );
        // also for mutating requests
        assert_eq!(
            decide(Some(TOKEN), None, true),
            AdminAuth::Unauthorized,
        );
    }

    #[test]
    fn non_bearer_scheme_is_unauthorized() {
        let hdr = format!("Basic {}", TOKEN);
        assert_eq!(
            decide(Some(TOKEN), Some(&hdr), false),
            AdminAuth::Unauthorized,
        );
    }

    #[test]
    fn token_prefix_is_not_accepted() {
        // ensure we require full equality, not a prefix match
        let hdr = "Bearer s3cr3t";
        assert_eq!(
            decide(Some(TOKEN), Some(hdr), false),
            AdminAuth::Unauthorized,
        );
    }

    // ── No token configured ──────────────────────────────────────

    #[test]
    fn no_token_allows_reads() {
        assert_eq!(decide(None, None, false), AdminAuth::Allow);
    }

    #[test]
    fn no_token_rejects_writes() {
        assert_eq!(
            decide(None, None, true),
            AdminAuth::WriteDisabled,
            "without a token, mutating endpoints must be disabled (403)",
        );
        // even if a stray Authorization header is present, writes stay disabled
        assert_eq!(
            decide(None, Some("Bearer whatever"), true),
            AdminAuth::WriteDisabled,
        );
    }

    // ── constant_time_eq ─────────────────────────────────────────

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
