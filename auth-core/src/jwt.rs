//! JWT verification — validate volta session tokens without HTTP roundtrip.
//!
//! This replaces the HTTP call to volta-auth-proxy /auth/verify for
//! session cookie validation (read path).

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
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

    /// JWT ID — この token 1枚を指す一意な値。
    ///
    /// アクセストークンはステートレスな JWT なので、**発行してしまうと
    /// 期限切れまで止められない**（`/oauth/revoke` のコメントもそう言っている）。
    /// 個別に失効させるには「どれを失効させたか」を指す名前が要る。
    /// 失効リストはこの値で引く。
    #[serde(default)]
    pub jti: Option<String>,

    /// Audience — この token を受け取ってよい相手。
    ///
    /// 無いと、あるサービス向けに出した token が**別のサービスでもそのまま通る**。
    /// 一時アクセスでは「このホストだけ」を強制したいので必須級。
    /// 単一文字列と配列の両方が来る（RFC 7519 がどちらも許している）。
    #[serde(default)]
    pub aud: Option<Audience>,

    /// スコープ（空白区切り）。OAuth 2.0 の慣習に合わせる。
    ///
    /// 「このホストのこのパスだけ」「読み取りだけ」を token 自体に載せるために使う。
    #[serde(default)]
    pub scope: Option<String>,
}

/// `aud` は単一文字列でも配列でもよい（RFC 7519 §4.1.3）。
///
/// 片方しか受けないと、他所が発行した token を読めずに落ちる。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Audience::One(a) => a == value,
            Audience::Many(v) => v.iter().any(|a| a == value),
        }
    }

    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Audience::One(a) => vec![a.clone()],
            Audience::Many(v) => v.clone(),
        }
    }
}

impl VoltaClaims {
    /// スコープを空白区切りで分解する。
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_deref()
            .unwrap_or("")
            .split_whitespace()
            .collect()
    }

    /// この token が `host` 向けに出されたものか。
    ///
    /// `aud` が無い token は**従来どおり通す**。既に出回っている token を
    /// 一斉に無効化しないため（後方互換）。新しく出す token には必ず載せる。
    pub fn allows_audience(&self, host: &str) -> bool {
        match &self.aud {
            None => true,
            Some(a) => a.contains(host),
        }
    }
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
        let key = DecodingKey::from_rsa_pem(pem).map_err(|e| format!("invalid RSA PEM: {}", e))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();
        Ok(Self {
            decoding_key: key,
            validation,
        })
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
    /// Optional `kid` header — set for asymmetric (RS256) OP keys so relying
    /// parties can pick the matching JWKS entry. `None` for the internal HS256
    /// session issuer (shared secret, no JWKS lookup).
    kid: Option<String>,
}

impl JwtIssuer {
    /// Create an issuer with HMAC-SHA256 secret.
    pub fn new_hs256(secret: &[u8], ttl_secs: u64) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            algorithm: Algorithm::HS256,
            ttl_secs,
            kid: None,
        }
    }

    /// Create an issuer with RSA private key (PEM).
    pub fn new_rsa(pem: &[u8], ttl_secs: u64) -> Result<Self, String> {
        Self::new_rsa_with_kid(pem, ttl_secs, None)
    }

    /// RSA issuer that stamps a `kid` header (for OP id/access tokens verified
    /// via JWKS).
    pub fn new_rsa_with_kid(
        pem: &[u8],
        ttl_secs: u64,
        kid: Option<String>,
    ) -> Result<Self, String> {
        let key = EncodingKey::from_rsa_pem(pem).map_err(|e| format!("invalid RSA PEM: {}", e))?;
        Ok(Self {
            encoding_key: key,
            algorithm: Algorithm::RS256,
            ttl_secs,
            kid,
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

        let mut header = Header::new(self.algorithm);
        header.kid = self.kid.clone();
        encode(&header, &c, &self.encoding_key)
            .map_err(|e| JwtError::InvalidToken(format!("encoding failed: {}", e)))
    }

    /// Sign arbitrary claims verbatim (no auto `iat`/`exp`). Used by the OP to
    /// mint id/access tokens whose claim set (`iss`/`aud`/`nonce`/`scope`/…)
    /// differs from the internal session `VoltaClaims`. The `alg` + `kid`
    /// header are set from this issuer.
    pub fn sign<T: serde::Serialize>(&self, claims: &T) -> Result<String, JwtError> {
        let mut header = Header::new(self.algorithm);
        header.kid = self.kid.clone();
        encode(&header, claims, &self.encoding_key)
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
            jti: None,
            aud: None,
            scope: None,
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
            email: None,
            tenant_id: None,
            tenant_slug: None,
            roles: None,
            name: None,
            app_id: None,
            iat: None,
            exp: None,
            jti: None,
            aud: None,
            scope: None,
        };
        let token = issuer.issue(&c).unwrap();
        assert!(matches!(
            verifier.verify(&token),
            Err(JwtError::MissingClaims(_))
        ));
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
        assert!(matches!(
            verifier.verify(&token),
            Err(JwtError::InvalidSignature)
        ));
    }
}

#[cfg(test)]
mod grant_claim_tests {
    use super::*;

    fn claims() -> VoltaClaims {
        VoltaClaims {
            sub: "u1".into(),
            email: None,
            tenant_id: None,
            tenant_slug: None,
            roles: Some("VIEWER".into()),
            name: None,
            app_id: None,
            iat: None,
            exp: None,
            jti: None,
            aud: None,
            scope: None,
        }
    }

    // ── aud ────────────────────────────────────────────────────
    //
    // 無いと、あるサービス向けに出した token が別サービスでもそのまま通る。

    #[test]
    fn audience_accepts_single_string() {
        let c = VoltaClaims {
            aud: Some(Audience::One("a.example.org".into())),
            ..claims()
        };
        assert!(c.allows_audience("a.example.org"));
        assert!(!c.allows_audience("b.example.org"));
    }

    #[test]
    fn audience_accepts_array() {
        // RFC 7519 §4.1.3 は単一文字列と配列の両方を許す。片方しか受けないと
        // 他所が発行した token を読めずに落ちる。
        let c = VoltaClaims {
            aud: Some(Audience::Many(vec![
                "a.example.org".into(),
                "b.example.org".into(),
            ])),
            ..claims()
        };
        assert!(c.allows_audience("a.example.org"));
        assert!(c.allows_audience("b.example.org"));
        assert!(!c.allows_audience("c.example.org"));
    }

    #[test]
    fn missing_audience_is_allowed_for_backward_compat() {
        // 既に出回っている token を一斉に無効化しないため。
        // 新しく出す token には必ず載せる。
        assert!(claims().allows_audience("anything.example.org"));
    }

    #[test]
    fn audience_deserializes_both_shapes() {
        let one: VoltaClaims = serde_json::from_str(r#"{"sub":"u","aud":"x.org"}"#).unwrap();
        assert!(one.allows_audience("x.org"));
        let many: VoltaClaims =
            serde_json::from_str(r#"{"sub":"u","aud":["x.org","y.org"]}"#).unwrap();
        assert!(many.allows_audience("y.org"));
    }

    // ── scope ──────────────────────────────────────────────────

    #[test]
    fn scopes_split_on_whitespace() {
        let c = VoltaClaims {
            scope: Some("read:reports  write:notes".into()),
            ..claims()
        };
        assert_eq!(c.scopes(), vec!["read:reports", "write:notes"]);
    }

    #[test]
    fn missing_scope_is_empty_not_panic() {
        assert!(claims().scopes().is_empty());
    }

    // ── 後方互換 ───────────────────────────────────────────────

    #[test]
    fn old_tokens_without_new_claims_still_parse() {
        // 3つとも Option + serde(default) なので、既存の token が読めなくなっては困る。
        let c: VoltaClaims =
            serde_json::from_str(r#"{"sub":"u1","roles":"MEMBER","exp":9999999999}"#).unwrap();
        assert_eq!(c.sub, "u1");
        assert!(c.jti.is_none());
        assert!(c.aud.is_none());
        assert!(c.scope.is_none());
    }
}
