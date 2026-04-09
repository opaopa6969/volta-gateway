//! Session verification — extract JWT from cookie and verify.
//!
//! This is the "in-process auth" that replaces the HTTP roundtrip
//! to volta-auth-proxy /auth/verify.

use crate::jwt::{JwtVerifier, JwtError, VoltaClaims};
use std::collections::HashMap;

/// Session verification result (compatible with gateway's AuthResult).
#[derive(Debug, Clone)]
pub enum SessionResult {
    /// Valid session — contains X-Volta-* headers.
    Valid(HashMap<String, String>),
    /// Session expired — redirect to login.
    Expired,
    /// Invalid session — deny access.
    Invalid(String),
    /// No session cookie found.
    NoSession,
}

/// Session verifier — extracts volta session cookie and verifies JWT.
#[derive(Clone)]
pub struct SessionVerifier {
    jwt: JwtVerifier,
    cookie_name: String,
}

impl SessionVerifier {
    pub fn new(jwt: JwtVerifier, cookie_name: &str) -> Self {
        Self { jwt, cookie_name: cookie_name.to_string() }
    }

    /// Verify session from cookie header string.
    /// Returns SessionResult with X-Volta-* headers on success.
    pub fn verify_cookie(&self, cookie_header: Option<&str>) -> SessionResult {
        let cookie = match cookie_header {
            Some(c) => c,
            None => return SessionResult::NoSession,
        };

        // Extract session token from cookie string
        let token = match extract_cookie_value(cookie, &self.cookie_name) {
            Some(t) => t,
            None => return SessionResult::NoSession,
        };

        // Verify JWT
        match self.jwt.verify_to_headers(token) {
            Ok(headers) => SessionResult::Valid(headers),
            Err(JwtError::Expired) => SessionResult::Expired,
            Err(e) => SessionResult::Invalid(e.to_string()),
        }
    }
}

/// Extract a named cookie value from a Cookie header string.
fn extract_cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtVerifier;

    fn test_verifier() -> JwtVerifier {
        JwtVerifier::new_hs256(b"test-secret-key-at-least-32-bytes!!")
    }

    #[test]
    fn extract_cookie_basic() {
        assert_eq!(
            extract_cookie_value("__volta_session=abc123; other=xyz", "__volta_session"),
            Some("abc123")
        );
    }

    #[test]
    fn extract_cookie_missing() {
        assert_eq!(
            extract_cookie_value("other=xyz", "__volta_session"),
            None
        );
    }

    #[test]
    fn extract_cookie_empty() {
        assert_eq!(extract_cookie_value("", "__volta_session"), None);
    }

    #[test]
    fn session_no_cookie() {
        let verifier = SessionVerifier::new(test_verifier(), "__volta_session");
        assert!(matches!(verifier.verify_cookie(None), SessionResult::NoSession));
    }

    #[test]
    fn session_missing_cookie_name() {
        let verifier = SessionVerifier::new(test_verifier(), "__volta_session");
        assert!(matches!(
            verifier.verify_cookie(Some("other=xyz")),
            SessionResult::NoSession
        ));
    }

    #[test]
    fn jwt_valid_token() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use crate::jwt::VoltaClaims;

        let secret = b"test-secret-key-at-least-32-bytes!!";
        let claims = VoltaClaims {
            sub: "user-123".into(),
            email: Some("test@example.com".into()),
            tenant_id: Some("tenant-1".into()),
            tenant_slug: None,
            roles: Some("ADMIN".into()),
            name: Some("Test User".into()),
            app_id: None,
            iat: Some(chrono::Utc::now().timestamp() as u64),
            exp: Some((chrono::Utc::now().timestamp() + 3600) as u64),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)).unwrap();
        let verifier = JwtVerifier::new_hs256(secret);
        let result = verifier.verify(&token);
        assert!(result.is_ok());
        let c = result.unwrap();
        assert_eq!(c.sub, "user-123");
        assert_eq!(c.email.unwrap(), "test@example.com");
    }

    #[test]
    fn jwt_to_volta_headers() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use crate::jwt::VoltaClaims;

        let secret = b"test-secret-key-at-least-32-bytes!!";
        let claims = VoltaClaims {
            sub: "user-456".into(),
            email: Some("u@test.com".into()),
            tenant_id: Some("t-1".into()),
            tenant_slug: Some("acme".into()),
            roles: Some("MEMBER".into()),
            name: Some("U".into()),
            app_id: None,
            iat: Some(chrono::Utc::now().timestamp() as u64),
            exp: Some((chrono::Utc::now().timestamp() + 3600) as u64),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)).unwrap();
        let verifier = JwtVerifier::new_hs256(secret);
        let headers = verifier.verify_to_headers(&token).unwrap();
        assert_eq!(headers.get("x-volta-user-id").unwrap(), "user-456");
        assert_eq!(headers.get("x-volta-email").unwrap(), "u@test.com");
        assert_eq!(headers.get("x-volta-tenant-slug").unwrap(), "acme");
    }

    #[test]
    fn jwt_expired_token() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use crate::jwt::VoltaClaims;

        let secret = b"test-secret-key-at-least-32-bytes!!";
        let claims = VoltaClaims {
            sub: "user-789".into(),
            email: None, tenant_id: None, tenant_slug: None,
            roles: None, name: None, app_id: None,
            iat: Some(1000),
            exp: Some(1001), // way in the past
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)).unwrap();
        let verifier = JwtVerifier::new_hs256(secret);
        assert!(matches!(verifier.verify(&token), Err(JwtError::Expired)));
    }

    #[test]
    fn jwt_wrong_secret() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use crate::jwt::VoltaClaims;

        let claims = VoltaClaims {
            sub: "u".into(), email: None, tenant_id: None, tenant_slug: None,
            roles: None, name: None, app_id: None,
            iat: Some(chrono::Utc::now().timestamp() as u64),
            exp: Some((chrono::Utc::now().timestamp() + 3600) as u64),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(b"secret-AAAAAAAAAAAAAAAAAAAAAAAAAA")).unwrap();
        let verifier = JwtVerifier::new_hs256(b"secret-BBBBBBBBBBBBBBBBBBBBBBBBBB");
        assert!(matches!(verifier.verify(&token), Err(JwtError::InvalidSignature)));
    }

    #[test]
    fn full_session_verify() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use crate::jwt::VoltaClaims;

        let secret = b"test-secret-key-at-least-32-bytes!!";
        let claims = VoltaClaims {
            sub: "user-full".into(),
            email: Some("full@test.com".into()),
            tenant_id: None, tenant_slug: None,
            roles: None, name: None, app_id: None,
            iat: Some(chrono::Utc::now().timestamp() as u64),
            exp: Some((chrono::Utc::now().timestamp() + 3600) as u64),
        };

        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret)).unwrap();
        let cookie = format!("__volta_session={}; other=xyz", token);

        let verifier = SessionVerifier::new(
            JwtVerifier::new_hs256(secret),
            "__volta_session",
        );

        match verifier.verify_cookie(Some(&cookie)) {
            SessionResult::Valid(headers) => {
                assert_eq!(headers.get("x-volta-user-id").unwrap(), "user-full");
                assert_eq!(headers.get("x-volta-email").unwrap(), "full@test.com");
            }
            other => panic!("expected Valid, got {:?}", other),
        }
    }
}
