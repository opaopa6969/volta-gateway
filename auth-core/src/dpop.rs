//! DPoP — OAuth 2.0 Demonstrating Proof of Possession (RFC 9449).
//!
//! A DPoP proof is a short-lived JWS the client signs with its own key pair and
//! sends in the `DPoP` header. The token endpoint binds the issued access token
//! to that key (`cnf.jkt` = JWK thumbprint), and resources then require a fresh
//! proof signed by the same key (+ `ath` hash of the presented token). A stolen
//! bearer token alone becomes useless.
//!
//! This module is the pure verification core: parse + verify a proof and return
//! its key thumbprint. Replay protection (`jti` cache) is the caller's job —
//! [`verify_proof`] hands back the `jti` so the HTTP layer can reject reuse.

use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Accepted clock skew / proof age, seconds (RFC 9449 recommends a small window).
const IAT_WINDOW_SECS: u64 = 300;

#[derive(Debug, PartialEq, Eq)]
pub enum DpopError {
    /// Structurally not a DPoP proof (bad JWS, missing jwk, wrong typ/alg).
    Malformed(String),
    /// Signature did not verify against the embedded JWK.
    BadSignature,
    /// htm/htu/iat/ath claim mismatch.
    ClaimMismatch(String),
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed DPoP proof: {m}"),
            Self::BadSignature => write!(f, "DPoP proof signature invalid"),
            Self::ClaimMismatch(m) => write!(f, "DPoP claim mismatch: {m}"),
        }
    }
}

/// A successfully verified proof.
#[derive(Debug, Clone)]
pub struct VerifiedProof {
    /// RFC 7638 JWK thumbprint (base64url SHA-256) — goes into `cnf.jkt`.
    pub jkt: String,
    /// Proof id — caller must reject replays within the iat window.
    pub jti: String,
}

#[derive(Deserialize)]
struct ProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    ath: Option<String>,
}

/// RFC 7638 thumbprint: SHA-256 over the canonical JSON of the required members
/// in lexicographic order, base64url-no-pad.
pub fn jwk_thumbprint(jwk: &Jwk) -> Result<String, DpopError> {
    let canonical = match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(p) => format!(
            "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            serde_json::to_value(&p.curve).ok().and_then(|v| v.as_str().map(String::from))
                .ok_or_else(|| DpopError::Malformed("bad curve".into()))?,
            p.x, p.y,
        ),
        AlgorithmParameters::RSA(p) => format!(
            "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
            p.e, p.n,
        ),
        _ => return Err(DpopError::Malformed("unsupported JWK key type".into())),
    };
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize()))
}

/// base64url(SHA-256(token)) — the `ath` claim (RFC 9449 §4.3).
pub fn access_token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize())
}

/// Verify a DPoP proof for `htm` (HTTP method) + `htu` (target URI, no
/// query/fragment). `access_token` must be provided at resource endpoints so
/// the `ath` binding is enforced; pass `None` at the token endpoint.
pub fn verify_proof(
    proof: &str,
    htm: &str,
    htu: &str,
    access_token: Option<&str>,
    now: u64,
) -> Result<VerifiedProof, DpopError> {
    let header = jsonwebtoken::decode_header(proof)
        .map_err(|e| DpopError::Malformed(e.to_string()))?;

    if header.typ.as_deref() != Some("dpop+jwt") {
        return Err(DpopError::Malformed("typ must be dpop+jwt".into()));
    }
    if !matches!(header.alg, Algorithm::ES256 | Algorithm::RS256) {
        return Err(DpopError::Malformed("alg must be ES256 or RS256".into()));
    }
    let jwk = header.jwk.as_ref()
        .ok_or_else(|| DpopError::Malformed("missing jwk header".into()))?;

    let key = DecodingKey::from_jwk(jwk)
        .map_err(|e| DpopError::Malformed(format!("bad jwk: {e}")))?;
    let mut validation = Validation::new(header.alg);
    validation.validate_exp = false; // freshness comes from iat, below
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<ProofClaims>(proof, &key, &validation)
        .map_err(|_| DpopError::BadSignature)?;
    let c = data.claims;

    if !c.htm.eq_ignore_ascii_case(htm) {
        return Err(DpopError::ClaimMismatch(format!("htm {} != {}", c.htm, htm)));
    }
    // Compare htu ignoring query/fragment on the presented value (RFC 9449 §4.3-8).
    let presented = c.htu.split(['?', '#']).next().unwrap_or("");
    if presented != htu {
        return Err(DpopError::ClaimMismatch(format!("htu {} != {}", presented, htu)));
    }
    if c.iat > now + IAT_WINDOW_SECS || c.iat + IAT_WINDOW_SECS < now {
        return Err(DpopError::ClaimMismatch("iat outside acceptance window".into()));
    }
    match (access_token, &c.ath) {
        (Some(tok), Some(ath)) => {
            use subtle::ConstantTimeEq;
            let expect = access_token_hash(tok);
            if expect.as_bytes().ct_eq(ath.as_bytes()).unwrap_u8() != 1 {
                return Err(DpopError::ClaimMismatch("ath does not match access token".into()));
            }
        }
        (Some(_), None) => return Err(DpopError::ClaimMismatch("ath required at resource".into())),
        (None, _) => {}
    }

    Ok(VerifiedProof { jkt: jwk_thumbprint(jwk)?, jti: c.jti })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// Generate an ES256 key pair; returns (EncodingKey, embedded-jwk).
    fn es256_key() -> (EncodingKey, Jwk) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        // uncompressed point: 0x04 || x(32) || y(32)
        let pubkey = pair.public_key().as_ref();
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": b64(&pubkey[1..33]), "y": b64(&pubkey[33..65]),
        })).unwrap();
        (EncodingKey::from_ec_der(pkcs8.as_ref()), jwk)
    }

    fn now() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
    }

    fn proof(key: &EncodingKey, jwk: &Jwk, htm: &str, htu: &str, iat: u64, ath: Option<String>) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(jwk.clone());
        let mut claims = serde_json::json!({
            "jti": uuid::Uuid::new_v4().to_string(), "htm": htm, "htu": htu, "iat": iat,
        });
        if let Some(a) = ath { claims["ath"] = serde_json::json!(a); }
        encode(&header, &claims, key).unwrap()
    }

    #[test]
    fn valid_proof_verifies_and_thumbprint_is_stable() {
        let (key, jwk) = es256_key();
        let p = proof(&key, &jwk, "POST", "https://as.example/oauth/token", now(), None);
        let v1 = verify_proof(&p, "POST", "https://as.example/oauth/token", None, now()).unwrap();
        // Same key → same jkt on a second proof.
        let p2 = proof(&key, &jwk, "POST", "https://as.example/oauth/token", now(), None);
        let v2 = verify_proof(&p2, "POST", "https://as.example/oauth/token", None, now()).unwrap();
        assert_eq!(v1.jkt, v2.jkt);
        assert_ne!(v1.jti, v2.jti);
    }

    #[test]
    fn htm_htu_iat_mismatches_rejected() {
        let (key, jwk) = es256_key();
        let t = now();
        let p = proof(&key, &jwk, "POST", "https://as.example/oauth/token", t, None);
        assert!(matches!(verify_proof(&p, "GET", "https://as.example/oauth/token", None, t), Err(DpopError::ClaimMismatch(_))));
        assert!(matches!(verify_proof(&p, "POST", "https://as.example/other", None, t), Err(DpopError::ClaimMismatch(_))));
        // stale iat
        let old = proof(&key, &jwk, "POST", "https://as.example/oauth/token", t - 4000, None);
        assert!(matches!(verify_proof(&old, "POST", "https://as.example/oauth/token", None, t), Err(DpopError::ClaimMismatch(_))));
        // htu query is ignored on the presented value
        let q = proof(&key, &jwk, "POST", "https://as.example/oauth/token?x=1", t, None);
        assert!(verify_proof(&q, "POST", "https://as.example/oauth/token", None, t).is_ok());
    }

    #[test]
    fn ath_binding_enforced_at_resource() {
        let (key, jwk) = es256_key();
        let t = now();
        let token = "the.access.token";
        // correct ath
        let good = proof(&key, &jwk, "GET", "https://as.example/userinfo", t, Some(access_token_hash(token)));
        assert!(verify_proof(&good, "GET", "https://as.example/userinfo", Some(token), t).is_ok());
        // wrong ath
        let bad = proof(&key, &jwk, "GET", "https://as.example/userinfo", t, Some(access_token_hash("other")));
        assert!(matches!(verify_proof(&bad, "GET", "https://as.example/userinfo", Some(token), t), Err(DpopError::ClaimMismatch(_))));
        // missing ath at a resource
        let none = proof(&key, &jwk, "GET", "https://as.example/userinfo", t, None);
        assert!(matches!(verify_proof(&none, "GET", "https://as.example/userinfo", Some(token), t), Err(DpopError::ClaimMismatch(_))));
    }

    #[test]
    fn wrong_key_signature_rejected() {
        let (key_a, _jwk_a) = es256_key();
        let (_key_b, jwk_b) = es256_key();
        // signed with A but advertising B's jwk → BadSignature
        let forged = proof(&key_a, &jwk_b, "POST", "https://as.example/oauth/token", now(), None);
        assert_eq!(
            verify_proof(&forged, "POST", "https://as.example/oauth/token", None, now()).unwrap_err(),
            DpopError::BadSignature
        );
    }

    #[test]
    fn typ_and_alg_gates() {
        let (key, jwk) = es256_key();
        // missing typ
        let mut header = Header::new(Algorithm::ES256);
        header.jwk = Some(jwk.clone());
        let claims = serde_json::json!({"jti":"x","htm":"POST","htu":"https://a/t","iat": now()});
        let no_typ = encode(&header, &claims, &key).unwrap();
        assert!(matches!(verify_proof(&no_typ, "POST", "https://a/t", None, now()), Err(DpopError::Malformed(_))));
    }
}
