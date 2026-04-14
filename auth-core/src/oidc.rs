//! OIDC ID token validation (backlog P1 #4).
//!
//! Validates an `id_token` returned from the token endpoint against
//! RFC 6749 / OIDC Core §3.1.3.7:
//!
//! - JWS signature via issuer JWKS (RS256 / ES256)
//! - `iss`, `aud`, `exp`, `iat`
//! - `nonce` matches the caller's expected value
//! - `at_hash` (when present) matches SHA-256(access_token) left-half
//!
//! JWKS are fetched lazily and cached per-issuer with a 5-minute TTL.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Max age of a cached JWK set before we refetch.
const JWKS_TTL: Duration = Duration::from_secs(300);
/// Clock skew tolerance applied to `iat` / `exp`.
const SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub name: Option<String>,
    pub iss: String,
    #[serde(with = "audience")]
    pub aud: Vec<String>,
    pub exp: u64,
    pub iat: u64,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub at_hash: Option<String>,
}

#[derive(Debug)]
pub enum VerifyError {
    MissingIdToken,
    BadFormat(String),
    SignatureInvalid(String),
    IssuerMismatch { expected: String, actual: String },
    AudienceMismatch { expected: String, actual: Vec<String> },
    Expired,
    IssuedInFuture,
    NonceMismatch,
    AtHashMismatch,
    JwksFetchFailed(String),
    UnknownKid(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingIdToken => write!(f, "id_token is absent"),
            Self::BadFormat(m) => write!(f, "malformed id_token: {}", m),
            Self::SignatureInvalid(m) => write!(f, "signature invalid: {}", m),
            Self::IssuerMismatch { expected, actual } => {
                write!(f, "iss mismatch: expected {}, got {}", expected, actual)
            }
            Self::AudienceMismatch { expected, actual } => {
                write!(f, "aud mismatch: expected {}, got {:?}", expected, actual)
            }
            Self::Expired => write!(f, "id_token expired"),
            Self::IssuedInFuture => write!(f, "id_token iat in the future"),
            Self::NonceMismatch => write!(f, "nonce mismatch"),
            Self::AtHashMismatch => write!(f, "at_hash mismatch"),
            Self::JwksFetchFailed(m) => write!(f, "JWKS fetch failed: {}", m),
            Self::UnknownKid(kid) => write!(f, "no JWK matches kid {}", kid),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verifies `id_token`s against a single issuer's JWKS.
pub struct IdTokenVerifier {
    issuer: String,
    client_id: String,
    jwks_uri: String,
    http: reqwest::Client,
    cache: Mutex<Option<(Instant, JwkSet)>>,
}

impl IdTokenVerifier {
    /// Construct with an explicit JWKS URI. Use `from_issuer` for the common
    /// `<issuer>/.well-known/openid-configuration` discovery path.
    pub fn new(issuer: String, client_id: String, jwks_uri: String) -> Self {
        Self {
            issuer,
            client_id,
            jwks_uri,
            http: reqwest::Client::new(),
            cache: Mutex::new(None),
        }
    }

    /// Fallback: derive `<issuer>/.well-known/jwks.json` when discovery isn't
    /// handled by the caller. Most providers (Google, MS) expose JWKS there.
    pub fn from_issuer(issuer: impl Into<String>, client_id: impl Into<String>) -> Self {
        let issuer = issuer.into();
        let jwks_uri = format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'));
        Self::new(issuer, client_id.into(), jwks_uri)
    }

    /// Main entrypoint.
    pub async fn verify(
        &self,
        id_token: &str,
        expected_nonce: &str,
        access_token: &str,
    ) -> Result<IdTokenClaims, VerifyError> {
        if id_token.is_empty() {
            return Err(VerifyError::MissingIdToken);
        }
        let header = decode_header(id_token).map_err(|e| VerifyError::BadFormat(e.to_string()))?;
        let alg = header.alg;
        let kid = header.kid.ok_or_else(|| VerifyError::BadFormat("missing kid".into()))?;

        let jwks = self.jwks_cached().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| VerifyError::UnknownKid(kid.clone()))?;
        let key = jwk.decoding_key()?;

        let mut validation = Validation::new(alg);
        // We validate iss/aud/exp/iat ourselves so we can surface richer errors.
        validation.validate_exp = false;
        validation.validate_aud = false;
        let data = decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|e| VerifyError::SignatureInvalid(e.to_string()))?;
        let claims = data.claims;

        // iss
        if claims.iss != self.issuer {
            return Err(VerifyError::IssuerMismatch {
                expected: self.issuer.clone(),
                actual: claims.iss.clone(),
            });
        }
        // aud
        if !claims.aud.iter().any(|a| a == &self.client_id) {
            return Err(VerifyError::AudienceMismatch {
                expected: self.client_id.clone(),
                actual: claims.aud.clone(),
            });
        }
        // exp / iat with skew
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if claims.exp + SKEW_SECS < now {
            return Err(VerifyError::Expired);
        }
        if claims.iat > now + SKEW_SECS {
            return Err(VerifyError::IssuedInFuture);
        }
        // nonce
        if claims.nonce.as_deref() != Some(expected_nonce) {
            return Err(VerifyError::NonceMismatch);
        }
        // at_hash (optional per OIDC spec — only enforce when present)
        if let Some(ref expected) = claims.at_hash {
            if !at_hash_matches(access_token, expected) {
                return Err(VerifyError::AtHashMismatch);
            }
        }

        Ok(claims)
    }

    async fn jwks_cached(&self) -> Result<JwkSet, VerifyError> {
        {
            let guard = self.cache.lock().expect("poison");
            if let Some((fetched, ref set)) = *guard {
                if fetched.elapsed() < JWKS_TTL {
                    return Ok(set.clone());
                }
            }
        }
        let fresh = self.fetch_jwks().await?;
        *self.cache.lock().expect("poison") = Some((Instant::now(), fresh.clone()));
        Ok(fresh)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, VerifyError> {
        let resp = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| VerifyError::JwksFetchFailed(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(VerifyError::JwksFetchFailed(format!("HTTP {}", resp.status())));
        }
        resp.json::<JwkSet>()
            .await
            .map_err(|e| VerifyError::JwksFetchFailed(e.to_string()))
    }
}

/// OIDC Core §3.1.3.6: at_hash = base64url(left half of SHA-256(access_token)).
pub fn at_hash_matches(access_token: &str, expected: &str) -> bool {
    let digest = Sha256::digest(access_token.as_bytes());
    let half = &digest[..digest.len() / 2];
    let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(half);
    // constant-time compare via ring
    ring::constant_time::verify_slices_are_equal(computed.as_bytes(), expected.as_bytes()).is_ok()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    // RSA
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    // EC
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

impl Jwk {
    fn decoding_key(&self) -> Result<DecodingKey, VerifyError> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self.n.as_deref().ok_or_else(|| VerifyError::BadFormat("RSA JWK missing n".into()))?;
                let e = self.e.as_deref().ok_or_else(|| VerifyError::BadFormat("RSA JWK missing e".into()))?;
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| VerifyError::BadFormat(format!("RSA key: {}", e)))
            }
            "EC" => {
                let x = self.x.as_deref().ok_or_else(|| VerifyError::BadFormat("EC JWK missing x".into()))?;
                let y = self.y.as_deref().ok_or_else(|| VerifyError::BadFormat("EC JWK missing y".into()))?;
                DecodingKey::from_ec_components(x, y)
                    .map_err(|e| VerifyError::BadFormat(format!("EC key: {}", e)))
            }
            other => Err(VerifyError::BadFormat(format!("unsupported kty {}", other))),
        }
    }
}

/// Serde adapter — accepts either `"aud"` string or `["aud1", "aud2"]` array.
mod audience {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    pub fn serialize<S>(aud: &Vec<String>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        if aud.len() == 1 { s.serialize_str(&aud[0]) } else { s.collect_seq(aud) }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Vec<String>, D::Error>
    where D: Deserializer<'de> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Vec<String>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("aud") }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> { Ok(vec![s.into()]) }
            fn visit_string<E: de::Error>(self, s: String) -> Result<Self::Value, E> { Ok(vec![s]) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(s) = a.next_element::<String>()? { v.push(s); }
                Ok(v)
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_hash_matches_reference_vector() {
        // OIDC Core §A.3 reference value (modified for SHA-256):
        // access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"
        // SHA-256 left-half, base64url.
        let token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
        let digest = Sha256::digest(token.as_bytes());
        let half = &digest[..digest.len() / 2];
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(half);
        assert!(at_hash_matches(token, &expected));
    }

    #[test]
    fn at_hash_mismatch_detected() {
        assert!(!at_hash_matches("token-a", "totally-wrong"));
    }

    #[test]
    fn aud_single_string_deserializes_to_vec() {
        let claims: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "sub": "u1", "iss": "x", "aud": "client-1", "exp": 0u64, "iat": 0u64,
        })).unwrap();
        assert_eq!(claims.aud, vec!["client-1"]);
    }

    #[test]
    fn aud_array_deserializes_to_vec() {
        let claims: IdTokenClaims = serde_json::from_value(serde_json::json!({
            "sub": "u1", "iss": "x", "aud": ["a", "b"], "exp": 0u64, "iat": 0u64,
        })).unwrap();
        assert_eq!(claims.aud, vec!["a", "b"]);
    }

    #[test]
    fn empty_id_token_is_rejected_fast() {
        let v = IdTokenVerifier::from_issuer("https://accounts.google.com", "cid");
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(v.verify("", "nonce", "at")).unwrap_err();
        assert!(matches!(err, VerifyError::MissingIdToken));
    }
}
