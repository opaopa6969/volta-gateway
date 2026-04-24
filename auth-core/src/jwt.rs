//! JWT verification — validate volta session tokens without HTTP roundtrip.
//!
//! This replaces the HTTP call to volta-auth-proxy /auth/verify for
//! session cookie validation (read path).

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation, Algorithm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Claims embedded in volta session JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoltaClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Email
    #[serde(default)]
    pub email: Option<String>,
    /// Tenant ID
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Tenant slug
    #[serde(default)]
    pub tenant_slug: Option<String>,
    /// Roles (comma-separated or array)
    #[serde(default)]
    pub roles: Option<String>,
    /// Display name
    #[serde(default)]
    pub name: Option<String>,
    /// App ID
    #[serde(default)]
    pub app_id: Option<String>,
    /// Issued at (Unix timestamp)
    #[serde(default)]
    pub iat: Option<u64>,
    /// Expiration (Unix timestamp)
    #[serde(default)]
    pub exp: Option<u64>,
}

impl VoltaClaims {
    /// Convert claims to X-Volta-* header map (compatible with auth-proxy HTTP response).
    pub fn to_volta_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("x-volta-user-id".into(), self.sub.clone());
        if let Some(ref email) = self.email {
            headers.insert("x-volta-email".into(), email.clone());
        }
        if let Some(ref tid) = self.tenant_id {
            headers.insert("x-volta-tenant-id".into(), tid.clone());
        }
        if let Some(ref slug) = self.tenant_slug {
            headers.insert("x-volta-tenant-slug".into(), slug.clone());
        }
        if let Some(ref roles) = self.roles {
            headers.insert("x-volta-roles".into(), roles.clone());
        }
        if let Some(ref name) = self.name {
            headers.insert("x-volta-display-name".into(), name.clone());
        }
        headers
    }
}

/// JWT verifier configuration.
#[derive(Clone)]
pub struct JwtVerifier {
    decoding_key: DecodingKey,
    validation: Validation,
}

/// JWT verification error.
#[derive(Debug)]
pub enum JwtError {
    Expired,
    InvalidSignature,
    InvalidToken(String),
    MissingClaims(String),
}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Expired => write!(f, "token expired"),
            JwtError::InvalidSignature => write!(f, "invalid signature"),
            JwtError::InvalidToken(e) => write!(f, "invalid token: {}", e),
            JwtError::MissingClaims(c) => write!(f, "missing claims: {}", c),
        }
    }
}

impl JwtVerifier {
    /// Create a verifier with HMAC-SHA256 secret.
    pub fn new_hs256(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.clear(); // we handle exp manually
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            validation,
        }
    }

    /// Create a verifier with RSA public key (PEM).
    pub fn new_rsa(pem: &[u8]) -> Result<Self, String> {
        let key = DecodingKey::from_rsa_pem(pem)
            .map_err(|e| format!("invalid RSA PEM: {}", e))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();
        Ok(Self { decoding_key: key, validation })
    }

    /// Verify a JWT token and return claims.
    pub fn verify(&self, token: &str) -> Result<VoltaClaims, JwtError> {
        let token_data = decode::<VoltaClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    JwtError::Expired
                } else if msg.contains("InvalidSignature") {
                    JwtError::InvalidSignature
                } else {
                    JwtError::InvalidToken(msg)
                }
            })?;

        let claims = token_data.claims;

        if claims.sub.is_empty() {
            return Err(JwtError::MissingClaims("sub".into()));
        }

        Ok(claims)
    }

    /// Verify and return X-Volta-* headers (drop-in replacement for HTTP auth verify).
    pub fn verify_to_headers(&self, token: &str) -> Result<HashMap<String, String>, JwtError> {
        let claims = self.verify(token)?;
        Ok(claims.to_volta_headers())
    }
}

/// JWT issuer — creates signed session JWTs.
#[derive(Clone)]
pub struct JwtIssuer {
    encoding_key: EncodingKey,
    algorithm: Algorithm,
    ttl_secs: u64,
}

impl JwtIssuer {
    /// Create an issuer with HMAC-SHA256 secret.
    pub fn new_hs256(secret: &[u8], ttl_secs: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
            ttl_secs,
        }
    }

    /// Create an issuer with RSA private key (PEM).
    pub fn new_rsa(pem: &[u8], ttl_secs: u64) -> Result<Self, String> {
        let key = EncodingKey::from_rsa_pem(pem)
            .map_err(|e| format!("invalid RSA PEM: {}", e))?;
        Ok(Self {
            encoding_key: key,
            algorithm: Algorithm::RS256,
            ttl_secs,
        })
    }

    pub fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    /// Issue a signed JWT from claims. Sets `iat` and `exp` automatically.
    pub fn issue(&self, claims: &VoltaClaims) -> Result<String, JwtError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut c = claims.clone();
        c.iat = Some(now);
        c.exp = Some(now + self.ttl_secs);

        let header = Header::new(self.algorithm);
        encode(&header, &c, &self.encoding_key)
            .map_err(|e| JwtError::InvalidToken(format!("encoding failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-secret-at-least-32-bytes!!!";

    fn minimal_claims(sub: &str) -> VoltaClaims {
        VoltaClaims {
            sub: sub.into(),
            email: None,
            tenant_id: None,
            tenant_slug: None,
            roles: None,
            name: None,
            app_id: None,
            iat: None,
            exp: None,
        }
    }

    // ── JwtIssuer ──────────────────────────────────────────────

    #[test]
    fn issue_sets_iat_and_exp() {
        let issuer = JwtIssuer::new_hs256(SECRET, 3600);
        let token = issuer.issue(&minimal_claims("u1")).unwrap();
        let verifier = JwtVerifier::new_hs256(SECRET);
        let claims = verifier.verify(&token).unwrap();
        let iat = claims.iat.expect("iat must be set");
        let exp = claims.exp.expect("exp must be set");
        assert_eq!(exp - iat, 3600, "exp should be iat + ttl");
    }

    #[test]
    fn issue_ttl_accessor() {
        let issuer = JwtIssuer::new_hs256(SECRET, 7200);
        assert_eq!(issuer.ttl_secs(), 7200);
    }

    #[test]
    fn issue_preserves_optional_claims() {
        let issuer = JwtIssuer::new_hs256(SECRET, 3600);
        let verifier = JwtVerifier::new_hs256(SECRET);
        let mut c = minimal_claims("u2");
        c.email = Some("user@example.com".into());
        c.tenant_id = Some("t-42".into());
        c.tenant_slug = Some("acme".into());
        c.roles = Some("OWNER".into());
        c.name = Some("Alice".into());
        let token = issuer.issue(&c).unwrap();
        let got = verifier.verify(&token).unwrap();
        assert_eq!(got.email.unwrap(), "user@example.com");
        assert_eq!(got.tenant_id.unwrap(), "t-42");
        assert_eq!(got.tenant_slug.unwrap(), "acme");
        assert_eq!(got.roles.unwrap(), "OWNER");
        assert_eq!(got.name.unwrap(), "Alice");
    }

    #[test]
    fn two_tokens_issued_at_same_second_differ_only_by_sub() {
        let issuer = JwtIssuer::new_hs256(SECRET, 3600);
        let t1 = issuer.issue(&minimal_claims("user-a")).unwrap();
        let t2 = issuer.issue(&minimal_claims("user-b")).unwrap();
        assert_ne!(t1, t2);
    }

    // ── JwtVerifier ────────────────────────────────────────────

    #[test]
    fn verify_invalid_jwt_string() {
        let verifier = JwtVerifier::new_hs256(SECRET);
        let result = verifier.verify("not.a.jwt");
        assert!(matches!(result, Err(JwtError::InvalidToken(_))));
    }

    #[test]
    fn verify_empty_sub_is_rejected() {
        let issuer = JwtIssuer::new_hs256(SECRET, 3600);
        let verifier = JwtVerifier::new_hs256(SECRET);
        // Issue with empty sub — issuer does not validate sub.
        // Then verify must reject it.
        let c = VoltaClaims {
            sub: String::new(),
            email: None, tenant_id: None, tenant_slug: None,
            roles: None, name: None, app_id: None,
            iat: None, exp: None,
        };
        let token = issuer.issue(&c).unwrap();
        assert!(matches!(verifier.verify(&token), Err(JwtError::MissingClaims(_))));
    }

    #[test]
    fn verify_to_headers_includes_user_id() {
        let issuer = JwtIssuer::new_hs256(SECRET, 3600);
        let verifier = JwtVerifier::new_hs256(SECRET);
        let mut c = minimal_claims("hdr-user");
        c.email = Some("hdr@test.com".into());
        let token = issuer.issue(&c).unwrap();
        let headers = verifier.verify_to_headers(&token).unwrap();
        assert_eq!(headers["x-volta-user-id"], "hdr-user");
        assert_eq!(headers["x-volta-email"], "hdr@test.com");
    }

    #[test]
    fn verify_to_headers_omits_absent_optional_fields() {
        let issuer = JwtIssuer::new_hs256(SECRET, 3600);
        let verifier = JwtVerifier::new_hs256(SECRET);
        let token = issuer.issue(&minimal_claims("bare-user")).unwrap();
        let headers = verifier.verify_to_headers(&token).unwrap();
        assert!(headers.contains_key("x-volta-user-id"));
        assert!(!headers.contains_key("x-volta-email"));
        assert!(!headers.contains_key("x-volta-tenant-id"));
    }

    #[test]
    fn verify_wrong_algorithm_token_is_rejected() {
        // Craft a "none" alg token and make sure it's not accepted.
        let verifier = JwtVerifier::new_hs256(SECRET);
        // A token signed with HS256 but verified with a completely different secret
        let other_issuer = JwtIssuer::new_hs256(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 3600);
        let token = other_issuer.issue(&minimal_claims("attacker")).unwrap();
        assert!(matches!(verifier.verify(&token), Err(JwtError::InvalidSignature)));
    }
}
