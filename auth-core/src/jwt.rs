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
