//! JWKS-backed RS256 session verification + multi-algorithm chain.
//!
//! The gateway's degraded-mode / in-process session verification needs to
//! accept the RS256 tokens that `volta-auth-proxy` issues (alg=RS256,
//! iss=volta-auth, aud=volta-apps), keyed by `kid` against the proxy's JWKS
//! endpoint (`/.well-known/jwks.json`). HS256 (shared secret) is retained for
//! backward compatibility.
//!
//! Verification order (see [`MultiVerifier::verify`]):
//!   1. RS256 via JWKS (kid lookup; force-refresh on kid miss)
//!   2. RS256 via static public-key PEM
//!   3. HS256 via shared secret
//! First success wins; if all are absent/invalid the token is rejected.
//!
//! The JWKS cache is TTL-based and refreshed both lazily (on `verify_async`
//! when a `kid` is missing) and, optionally, by a background task the caller
//! spawns via [`JwksCache::spawn_refresher`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, Algorithm};
use serde::Deserialize;

use crate::jwt::{VoltaClaims, JwtError};

/// Default time-to-live for a fetched JWK set before a refresh is attempted.
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(300);
/// Minimum spacing between forced refreshes (kid-miss), to avoid hammering the
/// JWKS endpoint when presented a stream of bogus `kid`s.
const FORCE_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// A minimal JWK (RSA only — that's what auth-proxy issues).
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Decoding keys indexed by `kid`, plus the time they were fetched.
struct CachedKeys {
    keys: HashMap<String, Arc<DecodingKey>>,
    fetched: Instant,
    /// Last time a forced (kid-miss) refresh was performed.
    last_forced: Option<Instant>,
}

/// TTL-based JWKS cache with kid lookup and forced refresh on kid miss.
///
/// Cloneable — clones share the same underlying cache and HTTP client.
#[derive(Clone)]
pub struct JwksCache {
    url: String,
    http: reqwest::Client,
    ttl: Duration,
    inner: Arc<Mutex<Option<CachedKeys>>>,
}

impl JwksCache {
    /// Build a cache for the given JWKS URL (e.g.
    /// `http://auth-proxy/.well-known/jwks.json`). No fetch happens here.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            http: reqwest::Client::new(),
            ttl: DEFAULT_JWKS_TTL,
            inner: Arc::new(Mutex::new(None)),
        }
    }

    /// Override the cache TTL (mostly for tests).
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Look up a cached decoding key by `kid` *without* touching the network.
    /// Returns `None` when the cache is empty or the kid is unknown.
    fn lookup(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        let guard = self.inner.lock().expect("jwks cache poisoned");
        guard.as_ref().and_then(|c| c.keys.get(kid).cloned())
    }

    /// Fetch the JWKS endpoint and replace the cache. Returns the key count.
    pub async fn refresh(&self) -> Result<usize, String> {
        let resp = self
            .http
            .get(&self.url)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("JWKS fetch HTTP {}", resp.status()));
        }
        let set: JwkSet = resp
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {e}"))?;

        let mut keys = HashMap::new();
        for jwk in &set.keys {
            if jwk.kty != "RSA" {
                continue; // auth-proxy issues RSA; ignore others defensively
            }
            let (n, e) = match (jwk.n.as_deref(), jwk.e.as_deref()) {
                (Some(n), Some(e)) => (n, e),
                _ => continue,
            };
            match DecodingKey::from_rsa_components(n, e) {
                Ok(k) => {
                    keys.insert(jwk.kid.clone(), Arc::new(k));
                }
                Err(err) => {
                    tracing::warn!(kid = %jwk.kid, error = %err, "skipping malformed JWK");
                }
            }
        }
        let count = keys.len();
        let mut guard = self.inner.lock().expect("jwks cache poisoned");
        let last_forced = guard.as_ref().and_then(|c| c.last_forced);
        *guard = Some(CachedKeys { keys, fetched: Instant::now(), last_forced });
        tracing::debug!(url = %self.url, keys = count, "JWKS refreshed");
        Ok(count)
    }

    /// Resolve a decoding key for `kid`, refreshing on a miss (rate-limited).
    async fn key_for_kid(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        if let Some(k) = self.lookup(kid) {
            return Some(k);
        }
        // kid miss or cold cache: refresh once (respecting TTL/force interval).
        let should_refresh = {
            let guard = self.inner.lock().expect("jwks cache poisoned");
            match guard.as_ref() {
                None => true,
                Some(c) => {
                    let ttl_due = c.fetched.elapsed() >= self.ttl;
                    let force_ok = c
                        .last_forced
                        .map(|t| t.elapsed() >= FORCE_REFRESH_MIN_INTERVAL)
                        .unwrap_or(true);
                    ttl_due || force_ok
                }
            }
        };
        if should_refresh {
            // mark forced-refresh time before awaiting to rate-limit concurrent misses
            {
                let mut guard = self.inner.lock().expect("jwks cache poisoned");
                if let Some(c) = guard.as_mut() {
                    c.last_forced = Some(Instant::now());
                }
            }
            if let Err(e) = self.refresh().await {
                tracing::warn!(error = %e, kid = %kid, "JWKS forced refresh failed");
                return None;
            }
        }
        self.lookup(kid)
    }

    /// Spawn a background task that refreshes the cache every `ttl`. The task
    /// runs until the returned `JoinHandle` is dropped/aborted or the process
    /// exits. An initial refresh is attempted immediately.
    pub fn spawn_refresher(&self) -> tokio::task::JoinHandle<()> {
        let cache = self.clone();
        tokio::spawn(async move {
            // initial population
            if let Err(e) = cache.refresh().await {
                tracing::warn!(url = %cache.url, error = %e, "initial JWKS refresh failed");
            }
            let mut interval = tokio::time::interval(cache.ttl);
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                if let Err(e) = cache.refresh().await {
                    tracing::warn!(url = %cache.url, error = %e, "periodic JWKS refresh failed");
                }
            }
        })
    }
}

/// RS256 verification config that validates iss/aud the way auth-proxy issues
/// them. `None` for either disables that particular check.
#[derive(Clone, Default)]
pub struct Rs256Validation {
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl Rs256Validation {
    fn build(&self) -> Validation {
        let mut v = Validation::new(Algorithm::RS256);
        v.validate_exp = true;
        v.required_spec_claims.clear();
        // jsonwebtoken validates aud by default; only enforce when configured.
        v.validate_aud = false;
        if let Some(iss) = &self.issuer {
            v.set_issuer(&[iss]);
        }
        if let Some(aud) = &self.audience {
            v.set_audience(&[aud]);
            v.validate_aud = true;
        }
        v
    }
}

/// A verifier that tries, in order: RS256/JWKS → RS256/PEM → HS256.
///
/// At least one source should be configured; with none configured every token
/// is rejected (`JwtError::InvalidToken`).
#[derive(Clone)]
pub struct MultiVerifier {
    jwks: Option<JwksCache>,
    rsa_pem: Option<Arc<DecodingKey>>,
    hs256: Option<Arc<DecodingKey>>,
    validation: Rs256Validation,
}

impl MultiVerifier {
    pub fn builder() -> MultiVerifierBuilder {
        MultiVerifierBuilder::default()
    }

    pub fn has_rs256(&self) -> bool {
        self.jwks.is_some() || self.rsa_pem.is_some()
    }

    pub fn has_hs256(&self) -> bool {
        self.hs256.is_some()
    }

    pub fn jwks(&self) -> Option<&JwksCache> {
        self.jwks.as_ref()
    }

    fn finalize(&self, claims: VoltaClaims) -> Result<VoltaClaims, JwtError> {
        if claims.sub.is_empty() {
            return Err(JwtError::MissingClaims("sub".into()));
        }
        Ok(claims)
    }

    /// Map a jsonwebtoken error into our error enum.
    fn map_err(e: jsonwebtoken::errors::Error) -> JwtError {
        let msg = e.to_string();
        if msg.contains("ExpiredSignature") {
            JwtError::Expired
        } else if msg.contains("InvalidSignature") {
            JwtError::InvalidSignature
        } else {
            JwtError::InvalidToken(msg)
        }
    }

    /// Try RS256 with an explicit decoding key.
    fn verify_rs256(&self, token: &str, key: &DecodingKey) -> Result<VoltaClaims, JwtError> {
        let validation = self.validation.build();
        let data = decode::<VoltaClaims>(token, key, &validation).map_err(Self::map_err)?;
        self.finalize(data.claims)
    }

    /// Try HS256 with the shared secret.
    fn verify_hs256(&self, token: &str, key: &DecodingKey) -> Result<VoltaClaims, JwtError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        let data = decode::<VoltaClaims>(token, key, &validation).map_err(Self::map_err)?;
        self.finalize(data.claims)
    }

    /// Async verify: enables JWKS kid lookup with forced refresh on miss.
    /// Order: RS256(JWKS) → RS256(PEM) → HS256.
    pub async fn verify_async(&self, token: &str) -> Result<VoltaClaims, JwtError> {
        let mut last_err = JwtError::InvalidToken("no verifier configured".into());

        // 1. RS256 via JWKS (needs the token header's kid).
        if let Some(ref jwks) = self.jwks {
            match decode_header(token) {
                Ok(header) if header.alg == Algorithm::RS256 => {
                    if let Some(kid) = header.kid.as_deref() {
                        if let Some(key) = jwks.key_for_kid(kid).await {
                            match self.verify_rs256(token, &key) {
                                Ok(c) => return Ok(c),
                                Err(e) => last_err = e,
                            }
                        } else {
                            last_err = JwtError::InvalidToken(format!("unknown kid {kid}"));
                        }
                    } else {
                        last_err = JwtError::InvalidToken("RS256 token missing kid".into());
                    }
                }
                _ => {}
            }
        }

        // 2. RS256 via static PEM.
        if let Some(ref pem_key) = self.rsa_pem {
            match self.verify_rs256(token, pem_key) {
                Ok(c) => return Ok(c),
                Err(e) => last_err = e,
            }
        }

        // 3. HS256 via shared secret.
        if let Some(ref hs) = self.hs256 {
            match self.verify_hs256(token, hs) {
                Ok(c) => return Ok(c),
                Err(e) => last_err = e,
            }
        }

        Err(last_err)
    }

    /// Sync verify (hot path): uses only the *cached* JWKS keys (no network),
    /// the static PEM, and HS256. Returns the chain's best error on failure.
    pub fn verify_sync(&self, token: &str) -> Result<VoltaClaims, JwtError> {
        let mut last_err = JwtError::InvalidToken("no verifier configured".into());

        if let Some(ref jwks) = self.jwks {
            if let Ok(header) = decode_header(token) {
                if header.alg == Algorithm::RS256 {
                    if let Some(kid) = header.kid.as_deref() {
                        if let Some(key) = jwks.lookup(kid) {
                            match self.verify_rs256(token, &key) {
                                Ok(c) => return Ok(c),
                                Err(e) => last_err = e,
                            }
                        } else {
                            last_err = JwtError::InvalidToken(format!("unknown kid {kid}"));
                        }
                    }
                }
            }
        }

        if let Some(ref pem_key) = self.rsa_pem {
            match self.verify_rs256(token, pem_key) {
                Ok(c) => return Ok(c),
                Err(e) => last_err = e,
            }
        }

        if let Some(ref hs) = self.hs256 {
            match self.verify_hs256(token, hs) {
                Ok(c) => return Ok(c),
                Err(e) => last_err = e,
            }
        }

        Err(last_err)
    }
}

/// Builder for [`MultiVerifier`].
#[derive(Default)]
pub struct MultiVerifierBuilder {
    jwks: Option<JwksCache>,
    rsa_pem: Option<Arc<DecodingKey>>,
    hs256: Option<Arc<DecodingKey>>,
    validation: Rs256Validation,
}

impl MultiVerifierBuilder {
    pub fn jwks(mut self, cache: JwksCache) -> Self {
        self.jwks = Some(cache);
        self
    }

    /// Add an RS256 public-key PEM source. On a malformed PEM the builder is
    /// returned unchanged alongside the error so the caller can continue.
    pub fn rsa_pem(mut self, pem: &[u8]) -> Result<Self, (Self, String)> {
        match DecodingKey::from_rsa_pem(pem) {
            Ok(key) => {
                self.rsa_pem = Some(Arc::new(key));
                Ok(self)
            }
            Err(e) => Err((self, format!("invalid RSA PEM: {e}"))),
        }
    }

    pub fn hs256(mut self, secret: &[u8]) -> Self {
        self.hs256 = Some(Arc::new(DecodingKey::from_secret(secret)));
        self
    }

    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.validation.issuer = Some(iss.into());
        self
    }

    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.validation.audience = Some(aud.into());
        self
    }

    pub fn build(self) -> MultiVerifier {
        MultiVerifier {
            jwks: self.jwks,
            rsa_pem: self.rsa_pem,
            hs256: self.hs256,
            validation: self.validation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtIssuer;
    use jsonwebtoken::{encode, EncodingKey, Header};

    // A throwaway 2048-bit RSA keypair (PKCS#8 + SPKI PEM) for tests.
    const RSA_PRIV: &str = include_str!("testdata/rsa_priv.pem");
    const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");
    const HS_SECRET: &[u8] = b"test-secret-at-least-32-bytes!!!";

    fn claims(sub: &str) -> VoltaClaims {
        VoltaClaims {
            sub: sub.into(),
            email: Some("x@y.z".into()),
            tenant_id: None, tenant_slug: None,
            roles: Some("MEMBER".into()), name: None, app_id: None,
            iat: None, exp: None,
        }
    }

    fn rs256_token(kid: Option<&str>, iss: Option<&str>, aud: Option<&str>) -> String {
        #[derive(serde::Serialize)]
        struct Full {
            sub: String,
            email: String,
            roles: String,
            iat: u64,
            exp: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            iss: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            aud: Option<String>,
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let body = Full {
            sub: "rs-user".into(),
            email: "x@y.z".into(),
            roles: "MEMBER".into(),
            iat: now,
            exp: now + 3600,
            iss: iss.map(String::from),
            aud: aud.map(String::from),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = kid.map(String::from);
        let key = EncodingKey::from_rsa_pem(RSA_PRIV.as_bytes()).unwrap();
        encode(&header, &body, &key).unwrap()
    }

    #[test]
    fn rs256_pem_verifies_valid_token() {
        let v = MultiVerifier::builder()
            .rsa_pem(RSA_PUB.as_bytes()).map_err(|(_, e)| e).unwrap()
            .build();
        let token = rs256_token(None, None, None);
        let c = v.verify_sync(&token).expect("should verify");
        assert_eq!(c.sub, "rs-user");
    }

    #[test]
    fn rs256_pem_detects_tampering() {
        let v = MultiVerifier::builder()
            .rsa_pem(RSA_PUB.as_bytes()).map_err(|(_, e)| e).unwrap()
            .build();
        let token = rs256_token(None, None, None);
        // Flip a character in the middle of the signature segment.
        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_string();
        let mid = sig.len() / 2;
        let mut bytes: Vec<char> = sig.chars().collect();
        bytes[mid] = if bytes[mid] == 'A' { 'B' } else { 'A' };
        let tampered_sig: String = bytes.into_iter().collect();
        parts[2] = &tampered_sig;
        let tampered = parts.join(".");
        assert!(v.verify_sync(&tampered).is_err(), "tampered token must be rejected");
    }

    #[test]
    fn rs256_validates_issuer_and_audience() {
        let v = MultiVerifier::builder()
            .rsa_pem(RSA_PUB.as_bytes()).map_err(|(_, e)| e).unwrap()
            .issuer("volta-auth")
            .audience("volta-apps")
            .build();
        // correct iss/aud → ok
        let good = rs256_token(None, Some("volta-auth"), Some("volta-apps"));
        assert!(v.verify_sync(&good).is_ok());
        // wrong issuer → rejected
        let bad_iss = rs256_token(None, Some("evil"), Some("volta-apps"));
        assert!(v.verify_sync(&bad_iss).is_err());
        // wrong audience → rejected
        let bad_aud = rs256_token(None, Some("volta-auth"), Some("nope"));
        assert!(v.verify_sync(&bad_aud).is_err());
    }

    #[test]
    fn hs256_fallback_when_no_rs256_match() {
        let v = MultiVerifier::builder()
            .rsa_pem(RSA_PUB.as_bytes()).map_err(|(_, e)| e).unwrap()
            .hs256(HS_SECRET)
            .build();
        // HS256 token — RS256 path won't match (alg mismatch), HS256 should.
        let issuer = JwtIssuer::new_hs256(HS_SECRET, 3600);
        let token = issuer.issue(&claims("hs-user")).unwrap();
        let c = v.verify_sync(&token).expect("HS256 fallback should verify");
        assert_eq!(c.sub, "hs-user");
    }

    #[test]
    fn hs256_wrong_secret_rejected() {
        let v = MultiVerifier::builder().hs256(b"the-correct-secret-key-32-bytes!").build();
        let issuer = JwtIssuer::new_hs256(b"a-different-secret-key-is-32bytes", 3600);
        let token = issuer.issue(&claims("u")).unwrap();
        assert!(v.verify_sync(&token).is_err());
    }

    #[test]
    fn no_verifier_rejects_everything() {
        let v = MultiVerifier::builder().build();
        let token = rs256_token(None, None, None);
        assert!(v.verify_sync(&token).is_err());
    }

    #[test]
    fn jwks_kid_selection_picks_right_key() {
        // Build a JWKS cache pre-populated with the test public key under "k1".
        let (n, e) = rsa_pub_components();
        let cache = JwksCache::new("http://unused");
        // inject directly (no network)
        {
            let mut keys = HashMap::new();
            let dk = DecodingKey::from_rsa_components(&n, &e).unwrap();
            keys.insert("k1".to_string(), Arc::new(dk));
            *cache.inner.lock().unwrap() = Some(CachedKeys {
                keys, fetched: Instant::now(), last_forced: None,
            });
        }

        let v = MultiVerifier::builder().jwks(cache).build();
        // token with matching kid → ok
        let good = rs256_token(Some("k1"), None, None);
        assert!(v.verify_sync(&good).is_ok());
        // token with unknown kid → rejected (no network in sync path)
        let bad = rs256_token(Some("nope"), None, None);
        assert!(v.verify_sync(&bad).is_err());
    }

    /// Extract base64url n/e from the test RSA public key by re-deriving from
    /// the private key via a temporary JWK round-trip is overkill; instead we
    /// hardcode by parsing the PEM with rsa crate-free path: use jsonwebtoken's
    /// inability to expose components means we ship precomputed values.
    fn rsa_pub_components() -> (String, String) {
        // Precomputed from testdata/rsa_pub.pem (see gen comment in testdata).
        let n = include_str!("testdata/rsa_n.txt").trim().to_string();
        let e = include_str!("testdata/rsa_e.txt").trim().to_string();
        (n, e)
    }

    /// Spawn a one-shot HTTP server returning the given body, return its URL.
    async fn serve_jwks_once(body: String) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(), body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                }
            }
        });
        format!("http://{addr}/.well-known/jwks.json")
    }

    #[tokio::test]
    async fn jwks_refresh_fetches_and_verifies_over_http() {
        let (n, e) = rsa_pub_components();
        let body = serde_json::json!({
            "keys": [ { "kty": "RSA", "kid": "remote-kid", "n": n, "e": e } ]
        }).to_string();
        let url = serve_jwks_once(body).await;

        let cache = JwksCache::new(url);
        let count = cache.refresh().await.expect("refresh should succeed");
        assert_eq!(count, 1, "one RSA key parsed");

        let v = MultiVerifier::builder().jwks(cache).build();
        let token = rs256_token(Some("remote-kid"), None, None);
        assert!(v.verify_sync(&token).is_ok(), "token with fetched kid verifies");
    }

    #[tokio::test]
    async fn jwks_async_force_refresh_on_cold_cache() {
        let (n, e) = rsa_pub_components();
        let body = serde_json::json!({
            "keys": [ { "kty": "RSA", "kid": "lazy-kid", "n": n, "e": e } ]
        }).to_string();
        let url = serve_jwks_once(body).await;

        // Cold cache (never refreshed): async verify must fetch on the kid miss.
        let cache = JwksCache::new(url);
        let v = MultiVerifier::builder().jwks(cache).build();
        let token = rs256_token(Some("lazy-kid"), None, None);
        let c = v.verify_async(&token).await.expect("async should force-refresh and verify");
        assert_eq!(c.sub, "rs-user");
    }
}
