//! OpenID Provider signing keys (Phase 3a, docs/auth-methods-landscape.md §5).
//!
//! The internal *session* JWT keeps its HS256 shared-secret contract (the
//! gateway verifies `X-Volta-JWT` with the same secret). To become an OP that
//! third-party relying parties can trust, id/access tokens must be signed with
//! an **asymmetric** key whose public half is published at
//! `/.well-known/jwks.json`. This module generates/loads that RSA key and
//! converts a public PEM into a JWK.

use base64::Engine;
use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use tracing::{info, warn};

use volta_auth_core::jwt::JwtIssuer;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::SigningKeyStore;

const RSA_BITS: usize = 2048;

/// Generate a fresh RSA keypair, returned as `(public SPKI PEM, private PKCS#8 PEM)`.
pub fn generate_rsa_pem() -> Result<(String, String), String> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, RSA_BITS).map_err(|e| e.to_string())?;
    let pub_key = RsaPublicKey::from(&priv_key);
    let private_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();
    let public_pem = pub_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| e.to_string())?;
    Ok((public_pem, private_pem))
}

/// Convert an RSA **public** PEM (SPKI) into a JWK object. Returns `None` if the
/// PEM is not a parseable RSA public key (e.g. legacy HS256 placeholder rows),
/// so the JWKS endpoint can simply skip it.
pub fn rsa_public_pem_to_jwk(public_pem: &str, kid: &str) -> Option<serde_json::Value> {
    let pk = RsaPublicKey::from_public_key_pem(public_pem).ok()?;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pk.e().to_bytes_be());
    Some(serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    }))
}

/// Ensure an active OP signing key exists (generating one on first boot), then
/// build the RS256 issuer that stamps its `kid`. Returns `None` (OP token
/// signing disabled) only if key generation/loading fails — the server still
/// runs for the HS256 session paths.
pub async fn bootstrap_op_issuer(db: &PgStore, ttl_secs: u64) -> Option<JwtIssuer> {
    // Reuse an existing RSA key if present & parseable; otherwise mint one.
    let active = match SigningKeyStore::load_active(db).await {
        Ok(a) => a,
        Err(e) => { warn!("signing key load failed: {e}"); None }
    };
    let usable = active.filter(|k| RsaPublicKey::from_public_key_pem(&k.public_key).is_ok());

    let (kid, private_pem) = if let Some(k) = usable {
        (k.kid, k.private_key)
    } else {
        let (public_pem, private_pem) = match generate_rsa_pem() {
            Ok(pair) => pair,
            Err(e) => { warn!("OP RSA keygen failed: {e}"); return None; }
        };
        let kid = uuid::Uuid::new_v4().to_string();
        if let Err(e) = SigningKeyStore::save(db, &kid, &public_pem, &private_pem).await {
            warn!("persisting OP signing key failed: {e}");
            return None;
        }
        info!(%kid, "generated OP RSA signing key (RS256)");
        (kid, private_pem)
    };

    match JwtIssuer::new_rsa_with_kid(private_pem.as_bytes(), ttl_secs, Some(kid.clone())) {
        Ok(issuer) => { info!(%kid, "OP RS256 issuer ready"); Some(issuer) }
        Err(e) => { warn!("OP issuer build failed: {e}"); None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volta_auth_core::jwt::{JwtVerifier, VoltaClaims};

    fn claims(sub: &str) -> VoltaClaims {
        VoltaClaims { sub: sub.into(), email: None, tenant_id: None, tenant_slug: None,
            roles: None, name: None, app_id: None, iat: None, exp: None }
    }

    #[test]
    fn generated_rsa_signs_and_verifies_rs256() {
        let (public_pem, private_pem) = generate_rsa_pem().unwrap();
        let issuer = JwtIssuer::new_rsa_with_kid(private_pem.as_bytes(), 3600, Some("k1".into())).unwrap();
        let token = issuer.issue(&claims("user-1")).unwrap();
        // kid present in the JWT header (decode the first base64url segment)
        let header_b64 = token.split('.').next().unwrap();
        let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["kid"], "k1");
        assert_eq!(header["alg"], "RS256");
        // verifiable with the matching public key
        let verifier = JwtVerifier::new_rsa(public_pem.as_bytes()).unwrap();
        assert_eq!(verifier.verify(&token).unwrap().sub, "user-1");
    }

    #[test]
    fn public_pem_becomes_jwk_and_junk_is_skipped() {
        let (public_pem, _priv) = generate_rsa_pem().unwrap();
        let jwk = rsa_public_pem_to_jwk(&public_pem, "kid-1").unwrap();
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS256");
        assert_eq!(jwk["kid"], "kid-1");
        assert!(jwk["n"].as_str().unwrap().len() > 100);
        // legacy HS256 placeholder (hex, not PEM) → skipped
        assert!(rsa_public_pem_to_jwk("deadbeefdeadbeef", "kid-2").is_none());
    }
}
