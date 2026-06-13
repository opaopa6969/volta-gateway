use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use http_body_util::Empty;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::AuthConfig;
use volta_auth_core::jwks::{JwksCache, MultiVerifier};
use volta_auth_core::jwt::JwtError;
use volta_auth_core::session::SessionResult;

/// In-process session verifier wrapping a [`MultiVerifier`] (RS256 jwks/pem →
/// HS256). Extracts the session cookie value and maps verification to a
/// [`SessionResult`], mirroring auth-core's `SessionVerifier` but with the
/// multi-algorithm chain and optional JWKS async refresh.
#[derive(Clone)]
pub struct SessionMultiVerifier {
    verifier: MultiVerifier,
    cookie_name: String,
}

impl SessionMultiVerifier {
    fn new(verifier: MultiVerifier, cookie_name: &str) -> Self {
        Self { verifier, cookie_name: cookie_name.to_string() }
    }

    /// Extract the named cookie value from a `Cookie:` header string.
    fn extract<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if let Some(rest) = pair.strip_prefix(&self.cookie_name) {
                if let Some(value) = rest.strip_prefix('=') {
                    return Some(value);
                }
            }
        }
        None
    }

    fn map(result: Result<volta_auth_core::jwt::VoltaClaims, JwtError>) -> SessionResult {
        match result {
            Ok(claims) => SessionResult::Valid(claims.to_volta_headers()),
            Err(JwtError::Expired) => SessionResult::Expired,
            Err(e) => SessionResult::Invalid(e.to_string()),
        }
    }

    /// Sync verification — JWKS uses only cached keys (no network). Retained as
    /// a non-async API for callers/tests; the proxy hot path uses the async
    /// variant so JWKS can refresh on a kid miss.
    #[allow(dead_code)]
    pub fn verify_cookie(&self, cookie_header: Option<&str>) -> SessionResult {
        let token = match cookie_header.and_then(|c| self.extract(c)) {
            Some(t) => t,
            None => return SessionResult::NoSession,
        };
        Self::map(self.verifier.verify_sync(token))
    }

    /// Async verification — JWKS may force-refresh on a kid miss.
    pub async fn verify_cookie_async(&self, cookie_header: Option<&str>) -> SessionResult {
        let token = match cookie_header.and_then(|c| self.extract(c)) {
            Some(t) => t.to_string(),
            None => return SessionResult::NoSession,
        };
        Self::map(self.verifier.verify_async(&token).await)
    }

    fn jwks(&self) -> Option<&JwksCache> {
        self.verifier.jwks()
    }
}

/// Result of volta /auth/verify call.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// 200 — authenticated. Contains X-Volta-* headers.
    Authenticated(HashMap<String, String>),
    /// 401/302 — redirect to login.
    Redirect(String),
    /// 403 — access denied.
    Denied,
    /// 5xx or timeout — volta is down.
    Error(String),
}

/// HTTP client for volta /auth/verify. Connection-pooled, fail-closed.
/// #33: Auth result cache entry.
#[derive(Clone)]
struct AuthCacheEntry {
    result: AuthResult,
    created: Instant,
}

#[derive(Clone)]
pub struct VoltaAuthClient {
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Empty<Bytes>>,
    base_url: String,
    verify_path: String,
    timeout: Duration,
    /// #33: Short-lived auth cache (cookie hash → result). TTL = 5s.
    auth_cache: Arc<Mutex<HashMap<u64, AuthCacheEntry>>>,
    cache_ttl: Duration,
    /// DD-005 Phase 0: In-process JWT session verifier (optional).
    /// RS256(jwks/pem) → HS256(secret) chain, keyed off the session cookie.
    session_verifier: Option<SessionMultiVerifier>,
    /// #51: Public-facing auth URL for redirect allowlist (e.g. https://auth.example.com).
    auth_public_url: Option<String>,
    /// DD-005 縮退運転: auth-proxy ダウン時に in-process JWT 検証へフォールバックする。
    /// デフォルト off（fail-closed のまま）。env `VOLTA_AUTH_DEGRADED_MODE=true` で opt-in。
    degraded_mode: bool,
    /// 縮退フォールバック発動回数（メトリクス auth_degraded_total）。
    degraded_total: Arc<AtomicU64>,
}

impl VoltaAuthClient {
    pub fn new(config: &AuthConfig) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(config.pool_max_idle)
            .build_http();

        // DD-005: Build the in-process verifier chain (RS256 jwks/pem → HS256).
        // auth-proxy issues RS256 (iss=volta-auth, aud=volta-apps); HS256 stays
        // as a backward-compat fallback when a shared secret is configured.
        let cookie_name = config.cookie_name.as_deref().unwrap_or("__volta_session");
        let mut builder = MultiVerifier::builder();
        let mut have_source = false;
        let mut jwks_url_log: Option<String> = None;

        // RS256 via JWKS (preferred when present).
        if let Some(url) = config.jwks_url.as_ref().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            builder = builder.jwks(JwksCache::new(url));
            have_source = true;
            jwks_url_log = Some(url.to_string());
            tracing::info!(jwks_url = url, "in-process RS256 JWKS verify enabled");
        }
        // RS256 via static public-key PEM (inline or file path).
        match config.resolve_public_key_pem() {
            Some(Ok(pem)) => match builder.rsa_pem(&pem) {
                Ok(b) => {
                    builder = b;
                    have_source = true;
                    tracing::info!("in-process RS256 PEM verify enabled");
                }
                Err((b, e)) => {
                    builder = b;
                    tracing::error!(error = %e, "jwt_public_key_pem invalid — RS256 PEM disabled");
                }
            },
            Some(Err(e)) => tracing::error!(error = %e, "jwt_public_key_pem unreadable — RS256 PEM disabled"),
            None => {}
        }
        // HS256 via shared secret (backward compat).
        if let Some(secret) = config.jwt_secret.as_ref().filter(|s| !s.is_empty()) {
            builder = builder.hs256(secret.as_bytes());
            have_source = true;
            tracing::info!("in-process HS256 (jwt_secret) verify enabled");
        }
        // iss/aud enforcement for RS256.
        if let Some(iss) = config.jwt_issuer.as_ref().filter(|s| !s.is_empty()) {
            builder = builder.issuer(iss.clone());
        }
        if let Some(aud) = config.jwt_audience.as_ref().filter(|s| !s.is_empty()) {
            builder = builder.audience(aud.clone());
        }

        let session_verifier = if have_source {
            tracing::info!(cookie = cookie_name, "in-process session verify enabled");
            Some(SessionMultiVerifier::new(builder.build(), cookie_name))
        } else {
            None
        };
        let _ = jwks_url_log;

        // DD-005 縮退運転: config の degraded_mode（env VOLTA_AUTH_DEGRADED_MODE が
        // 優先フォールバック）。デフォルト off（安全側）。
        let degraded_mode = config.degraded_mode_enabled();
        if degraded_mode {
            if session_verifier.is_some() {
                tracing::warn!(
                    "auth degraded mode ENABLED: on auth-proxy failure, requests with a valid \
                     in-process-verifiable session JWT will be allowed (existing sessions only; \
                     new logins still require auth-proxy)"
                );
            } else {
                tracing::warn!(
                    "auth degraded mode requested but no in-process verifier configured \
                     (set auth.jwks_url / jwt_public_key_pem / jwt_secret) — fallback cannot \
                     verify sessions, staying fail-closed"
                );
            }
        }

        Self {
            client,
            base_url: config.volta_url.clone(),
            verify_path: config.verify_path.clone(),
            timeout: Duration::from_millis(config.timeout_ms),
            auth_cache: Arc::new(Mutex::new(HashMap::new())),
            cache_ttl: Duration::from_secs(5),
            session_verifier,
            auth_public_url: config.auth_public_url.clone(),
            degraded_mode,
            degraded_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 縮退フォールバック発動回数（メトリクス auth_degraded_total 用）。
    pub fn degraded_total(&self) -> u64 {
        self.degraded_total.load(Ordering::Relaxed)
    }

    /// Spawn the JWKS background refresher when a `jwks_url` is configured.
    /// Call once at startup (after the tokio runtime is up). No-op otherwise.
    pub fn spawn_jwks_refresher(&self) {
        if let Some(verifier) = self.session_verifier.as_ref() {
            if let Some(jwks) = verifier.jwks() {
                tracing::info!(jwks_url = jwks.url(), "starting JWKS background refresher");
                jwks.spawn_refresher();
            }
        }
    }

    /// DD-005 縮退運転のフォールバック判定。
    /// auth-proxy 由来の `AuthResult::Error` を受け取り、
    /// - degraded_mode off → そのまま fail-closed（Error を返す）
    /// - degraded_mode on + 有効セッション JWT → Authenticated（warn ログ + メトリクス）
    /// - degraded_mode on + JWT 無し/期限切れ/検証失敗 → fail-closed（Error を維持）
    async fn degraded_fallback(&self, host: &str, cookie: Option<&str>, err_msg: String) -> AuthResult {
        if !self.degraded_mode {
            return AuthResult::Error(err_msg);
        }
        let verifier = match self.session_verifier.as_ref() {
            Some(v) => v,
            // 検証手段が無いので fail-closed のまま。
            None => return AuthResult::Error(err_msg),
        };

        match verifier.verify_cookie_async(cookie).await {
            SessionResult::Valid(headers) => {
                let n = self.degraded_total.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    host = %host,
                    auth_error = %err_msg,
                    auth_degraded_total = n,
                    "auth degraded fallback: auth-proxy down, allowing request via in-process \
                     session JWT verify (existing session)"
                );
                AuthResult::Authenticated(headers)
            }
            // JWT 無し/期限切れ/検証失敗 → auth-proxy 無しでは新規認可できないため fail-closed。
            _ => AuthResult::Error(err_msg),
        }
    }

    /// Call volta /auth/verify with forwarded headers and cookies.
    /// #33: Results are cached for 5s by cookie hash to skip redundant calls.
    /// `client_ip` is the resolved real client IP, forwarded as X-Real-IP so
    /// the auth proxy can apply IP-based rules (e.g. local network bypass).
    pub async fn check(
        &self,
        host: &str,
        uri: &str,
        proto: &str,
        cookie: Option<&str>,
        app_id: Option<&str>,
        client_ip: Option<&str>,
    ) -> AuthResult {
        // DD-005 Phase 0: In-process JWT verify (skip HTTP roundtrip).
        // async path → JWKS may force-refresh on a cold cache / kid miss.
        if let Some(ref verifier) = self.session_verifier {
            match verifier.verify_cookie_async(cookie).await {
                SessionResult::Valid(headers) => {
                    tracing::trace!(host = %host, "auth: in-process JWT verify OK");
                    return AuthResult::Authenticated(headers);
                }
                SessionResult::Expired => {
                    return AuthResult::Redirect("/login".into());
                }
                SessionResult::Invalid(e) => {
                    tracing::debug!(host = %host, error = %e, "auth: JWT invalid, falling back to HTTP");
                    // Fall through to HTTP verify — token may be in a format auth-core doesn't handle
                }
                SessionResult::NoSession => {
                    // No session cookie — fall through to HTTP verify (may redirect to login)
                }
            }
        }

        // #33: Auth cache lookup
        let cache_key = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            cookie.unwrap_or("").hash(&mut h);
            host.hash(&mut h);
            app_id.unwrap_or("").hash(&mut h);
            h.finish()
        };
        {
            let cache = self.auth_cache.lock().unwrap();
            if let Some(entry) = cache.get(&cache_key) {
                if entry.created.elapsed() < self.cache_ttl {
                    return entry.result.clone();
                }
            }
        }

        let url = format!("{}{}", self.base_url, self.verify_path);

        let mut builder = Request::builder()
            .method("GET")
            .uri(url.parse::<Uri>().unwrap_or_default())
            .header("X-Forwarded-Host", host)
            .header("X-Forwarded-Uri", uri)
            .header("X-Forwarded-Proto", proto);

        if let Some(c) = cookie {
            builder = builder.header("Cookie", c);
        }
        if let Some(id) = app_id {
            builder = builder.header("X-Volta-App-Id", id);
        }
        if let Some(ip) = client_ip {
            builder = builder.header("X-Real-IP", ip);
        }

        let req = match builder.body(Empty::<Bytes>::new()) {
            Ok(r) => r,
            Err(e) => return AuthResult::Error(format!("build request: {e}")),
        };

        let result = tokio::time::timeout(self.timeout, self.client.request(req)).await;

        let auth_result = match result {
            Ok(Ok(resp)) => {
                let status = resp.status().as_u16();
                match status {
                    200 => {
                        let mut volta_headers = HashMap::new();
                        for (name, value) in resp.headers() {
                            let key = name.as_str();
                            if key.starts_with("x-volta-") {
                                if let Ok(v) = value.to_str() {
                                    volta_headers.insert(key.to_string(), v.to_string());
                                }
                            }
                        }
                        AuthResult::Authenticated(volta_headers)
                    }
                    401 => {
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("/login")
                            .to_string();
                        // #51: Validate redirect destination (open redirect prevention)
                        AuthResult::Redirect(sanitize_redirect(&location, self.auth_public_url.as_deref()))
                    }
                    302 => {
                        let location = resp
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("/login")
                            .to_string();
                        AuthResult::Redirect(sanitize_redirect(&location, self.auth_public_url.as_deref()))
                    }
                    403 => AuthResult::Denied,
                    _ => AuthResult::Error(format!("volta returned {status}")),
                }
            }
            Ok(Err(e)) => AuthResult::Error(format!("volta request failed: {e}")),
            Err(_) => AuthResult::Error("volta auth timeout".into()),
        };

        // DD-005 縮退運転: auth-proxy がダウン（timeout/5xx → AuthResult::Error）した場合、
        // degraded_mode が有効かつ有効なセッション JWT を持つリクエストだけ in-process 検証で通す。
        // JWT 無し/期限切れ/検証失敗は従来通り fail-closed（Error を維持）。
        let auth_result = match auth_result {
            AuthResult::Error(msg) => self.degraded_fallback(host, cookie, msg).await,
            other => other,
        };

        // #33: Cache successful auth results (5s TTL)
        if matches!(auth_result, AuthResult::Authenticated(_)) {
            let mut cache = self.auth_cache.lock().unwrap();
            cache.insert(cache_key, AuthCacheEntry {
                result: auth_result.clone(),
                created: Instant::now(),
            });
            // GC: remove expired entries (simple cap)
            if cache.len() > 10_000 {
                cache.retain(|_, e| e.created.elapsed() < self.cache_ttl);
            }
        }

        auth_result
    }

    /// Health check — is volta alive?
    pub async fn health(&self) -> bool {
        let url = format!("{}/healthz", self.base_url);
        let req = Request::builder()
            .uri(url.parse::<Uri>().unwrap_or_default())
            .body(Empty::<Bytes>::new());

        match req {
            Ok(r) => {
                let result = tokio::time::timeout(
                    Duration::from_secs(2),
                    self.client.request(r),
                ).await;
                matches!(result, Ok(Ok(resp)) if resp.status().is_success())
            }
            Err(_) => false,
        }
    }
}

/// #51: Sanitize redirect URL — only allow relative paths or auth-proxy origin.
/// Prevents open redirect attacks via compromised auth-proxy responses.
fn sanitize_redirect(url: &str, auth_public_url: Option<&str>) -> String {
    // Relative paths are always safe
    if url.starts_with('/') && !url.starts_with("//") {
        return url.to_string();
    }
    // Allow absolute redirects to the configured auth public URL (e.g. https://auth.example.com)
    if let Some(base) = auth_public_url {
        let base = base.trim_end_matches('/');
        if !base.is_empty() && url.starts_with(base) {
            return url.to_string();
        }
    }
    // Reject everything else (external sites)
    "/login".to_string()
}

#[cfg(test)]
mod degraded_tests {
    use super::*;
    use crate::config::AuthConfig;
    use volta_auth_core::jwt::{JwtIssuer, VoltaClaims};

    const SECRET: &str = "test-secret-key-at-least-32-bytes!!";

    fn empty_claims(sub: &str) -> VoltaClaims {
        VoltaClaims {
            sub: sub.into(),
            email: None, tenant_id: None, tenant_slug: None,
            roles: None, name: None, app_id: None,
            iat: None, exp: None,
        }
    }

    fn base_config() -> AuthConfig {
        AuthConfig {
            volta_url: "http://127.0.0.1:9".into(), // unreachable port → forces HTTP error
            verify_path: "/auth/verify".into(),
            timeout_ms: 200,
            pool_max_idle: 4,
            jwt_secret: Some(SECRET.into()),
            cookie_name: Some("__volta_session".into()),
            auth_public_url: None,
            degraded_mode: false,
            jwt_public_key_pem: None,
            jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
        }
    }

    /// Build a client with degraded_mode forced to a known value (bypasses env).
    fn client(degraded: bool) -> VoltaAuthClient {
        let mut c = VoltaAuthClient::new(&base_config());
        c.degraded_mode = degraded;
        c
    }

    /// Build a client with jwt_secret = None (no in-process verifier available).
    fn client_no_secret(degraded: bool) -> VoltaAuthClient {
        let mut cfg = base_config();
        cfg.jwt_secret = None;
        let mut c = VoltaAuthClient::new(&cfg);
        c.degraded_mode = degraded;
        c
    }

    fn valid_cookie() -> String {
        // JwtIssuer は iat/exp を now/now+ttl で自動設定する → 有効なトークン。
        let issuer = JwtIssuer::new_hs256(SECRET.as_bytes(), 3600);
        let mut c = empty_claims("user-degraded");
        c.email = Some("d@test.com".into());
        c.roles = Some("MEMBER".into());
        let token = issuer.issue(&c).unwrap();
        format!("__volta_session={}; foo=bar", token)
    }

    // ── degraded_fallback: the core decision ──────────────────────

    #[tokio::test]
    async fn down_with_valid_jwt_passes_when_degraded_on() {
        let c = client(true);
        let r = c.degraded_fallback("h", Some(&valid_cookie()), "timeout".into()).await;
        match r {
            AuthResult::Authenticated(h) => {
                assert_eq!(h.get("x-volta-user-id").unwrap(), "user-degraded");
            }
            other => panic!("expected Authenticated, got {:?}", other),
        }
        assert_eq!(c.degraded_total(), 1, "metric must increment");
    }

    #[tokio::test]
    async fn down_without_jwt_is_rejected_when_degraded_on() {
        let c = client(true);
        let r = c.degraded_fallback("h", None, "timeout".into()).await;
        assert!(matches!(r, AuthResult::Error(_)), "no JWT → fail-closed");
        assert_eq!(c.degraded_total(), 0);
    }

    #[tokio::test]
    async fn down_with_invalid_jwt_is_rejected_when_degraded_on() {
        let c = client(true);
        let bad = "__volta_session=not.a.real.jwt";
        let r = c.degraded_fallback("h", Some(bad), "timeout".into()).await;
        assert!(matches!(r, AuthResult::Error(_)), "invalid JWT → fail-closed");
        assert_eq!(c.degraded_total(), 0);
    }

    #[tokio::test]
    async fn degraded_off_always_fail_closed_even_with_valid_jwt() {
        let c = client(false);
        let r = c.degraded_fallback("h", Some(&valid_cookie()), "timeout".into()).await;
        assert!(matches!(r, AuthResult::Error(_)),
            "degraded_mode off → always fail-closed");
        assert_eq!(c.degraded_total(), 0);
    }

    #[tokio::test]
    async fn degraded_on_but_no_secret_stays_fail_closed() {
        // 検証手段が無い → valid に見えても通さない。
        let c = client_no_secret(true);
        let r = c.degraded_fallback("h", Some(&valid_cookie()), "timeout".into()).await;
        assert!(matches!(r, AuthResult::Error(_)));
        assert_eq!(c.degraded_total(), 0);
    }

    // ── end-to-end via check(): auth-proxy unreachable ────────────
    // jwt_secret 設定時、有効 JWT は Phase 0 の早期 in-process 検証で通る
    // （auth-proxy ダウンに依存せず生存する）ことを確認。

    #[tokio::test]
    async fn check_valid_session_survives_proxy_down() {
        let c = client(true);
        let cookie = valid_cookie();
        let r = c.check("h", "/", "https", Some(&cookie), None, None).await;
        assert!(matches!(r, AuthResult::Authenticated(_)),
            "valid session must survive auth-proxy outage");
    }

    #[tokio::test]
    async fn check_no_session_proxy_down_fail_closed_when_off() {
        let c = client(false);
        // クッキー無し → Phase 0 は NoSession で fall-through → HTTP 失敗 → degraded off → Error
        let r = c.check("h", "/", "https", None, None, None).await;
        assert!(matches!(r, AuthResult::Error(_)));
    }

    // ── degraded_mode config / env precedence ─────────────────────

    /// A serial guard so env-var-mutating tests don't race each other.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn degraded_mode_from_config_yaml_true() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
        let mut cfg = base_config();
        cfg.degraded_mode = true;
        assert!(cfg.degraded_mode_enabled(), "yaml true → enabled");
        cfg.degraded_mode = false;
        assert!(!cfg.degraded_mode_enabled(), "yaml false → disabled");
    }

    #[test]
    fn degraded_mode_env_overrides_yaml() {
        let _g = ENV_LOCK.lock().unwrap();
        let mut cfg = base_config();
        // env true overrides yaml false
        cfg.degraded_mode = false;
        std::env::set_var("VOLTA_AUTH_DEGRADED_MODE", "on");
        assert!(cfg.degraded_mode_enabled(), "env on → enabled despite yaml false");
        // env false overrides yaml true
        cfg.degraded_mode = true;
        std::env::set_var("VOLTA_AUTH_DEGRADED_MODE", "0");
        assert!(!cfg.degraded_mode_enabled(), "env 0 → disabled despite yaml true");
        // empty env → falls back to yaml
        std::env::set_var("VOLTA_AUTH_DEGRADED_MODE", "");
        cfg.degraded_mode = true;
        assert!(cfg.degraded_mode_enabled(), "empty env → yaml value");
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
    }

    #[test]
    fn client_reads_degraded_from_config_when_env_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
        let mut cfg = base_config();
        cfg.degraded_mode = true;
        let c = VoltaAuthClient::new(&cfg);
        assert!(c.degraded_mode, "config degraded_mode=true wired into client");
    }

    // ── RS256 in-process verification ─────────────────────────────

    const RSA_PRIV: &str = include_str!("testdata/rsa_priv.pem");
    const RSA_PUB: &str = include_str!("testdata/rsa_pub.pem");

    fn rs256_cookie(iss: Option<&str>, aud: Option<&str>) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
        #[derive(serde::Serialize)]
        struct Body {
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
        let body = Body {
            sub: "rs-user".into(),
            email: "rs@test.com".into(),
            roles: "MEMBER".into(),
            iat: now,
            exp: now + 3600,
            iss: iss.map(String::from),
            aud: aud.map(String::from),
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".into());
        let key = EncodingKey::from_rsa_pem(RSA_PRIV.as_bytes()).unwrap();
        let token = encode(&header, &body, &key).unwrap();
        format!("__volta_session={}", token)
    }

    /// Config wired with an inline RS256 public-key PEM (no HS256), degraded on.
    fn rs256_config() -> AuthConfig {
        let mut cfg = base_config();
        cfg.jwt_secret = None; // RS256 only
        cfg.jwt_public_key_pem = Some(RSA_PUB.into());
        cfg.jwt_issuer = Some("volta-auth".into());
        cfg.jwt_audience = Some("volta-apps".into());
        cfg
    }

    #[tokio::test]
    async fn rs256_valid_token_survives_proxy_down() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
        let mut c = VoltaAuthClient::new(&rs256_config());
        c.degraded_mode = true;
        let cookie = rs256_cookie(Some("volta-auth"), Some("volta-apps"));
        // auth-proxy unreachable → Phase 0 in-process RS256 verify must pass.
        let r = c.check("h", "/", "https", Some(&cookie), None, None).await;
        match r {
            AuthResult::Authenticated(h) => {
                assert_eq!(h.get("x-volta-user-id").unwrap(), "rs-user");
            }
            other => panic!("expected Authenticated, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn rs256_tampered_token_is_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
        let mut c = VoltaAuthClient::new(&rs256_config());
        c.degraded_mode = true;
        let cookie = rs256_cookie(Some("volta-auth"), Some("volta-apps"));
        // Corrupt a char in the signature (last segment).
        let mut parts: Vec<&str> = cookie.split('.').collect();
        let sig = parts[2].to_string();
        let mut chars: Vec<char> = sig.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'A' { 'B' } else { 'A' };
        let bad_sig: String = chars.into_iter().collect();
        parts[2] = &bad_sig;
        let tampered = parts.join(".");
        let r = c.check("h", "/", "https", Some(&tampered), None, None).await;
        assert!(matches!(r, AuthResult::Error(_)),
            "tampered RS256 token must fail-closed (proxy down)");
    }

    #[tokio::test]
    async fn rs256_wrong_issuer_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
        let mut c = VoltaAuthClient::new(&rs256_config());
        c.degraded_mode = true;
        let cookie = rs256_cookie(Some("evil-issuer"), Some("volta-apps"));
        let r = c.check("h", "/", "https", Some(&cookie), None, None).await;
        assert!(matches!(r, AuthResult::Error(_)),
            "wrong iss must be rejected");
    }

    #[test]
    fn resolve_public_key_pem_inline_and_path() {
        // inline PEM
        let mut cfg = base_config();
        cfg.jwt_public_key_pem = Some(RSA_PUB.into());
        let got = cfg.resolve_public_key_pem().unwrap().unwrap();
        assert!(String::from_utf8_lossy(&got).contains("BEGIN PUBLIC KEY"));
        // file path
        cfg.jwt_public_key_pem = Some("src/testdata/rsa_pub.pem".into());
        let got = cfg.resolve_public_key_pem().unwrap().unwrap();
        assert!(String::from_utf8_lossy(&got).contains("BEGIN PUBLIC KEY"));
        // unset
        cfg.jwt_public_key_pem = None;
        assert!(cfg.resolve_public_key_pem().is_none());
    }

    /// HS256 backward-compat still works alongside RS256 config.
    #[tokio::test]
    async fn hs256_backward_compat_alongside_rs256() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("VOLTA_AUTH_DEGRADED_MODE");
        let mut cfg = base_config(); // has jwt_secret (HS256)
        cfg.jwt_public_key_pem = Some(RSA_PUB.into());
        let mut c = VoltaAuthClient::new(&cfg);
        c.degraded_mode = true;
        // HS256 cookie (signed with SECRET) must still verify via the chain.
        let r = c.check("h", "/", "https", Some(&valid_cookie()), None, None).await;
        assert!(matches!(r, AuthResult::Authenticated(_)),
            "HS256 token must still verify when RS256 is also configured");
    }
}
