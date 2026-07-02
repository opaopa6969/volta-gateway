//! OpenID Provider (OP) endpoints — Phase 3b, docs/auth-methods-landscape.md §5.
//!
//! Makes volta an authorization server / IdP for downstream apps:
//!   GET  /.well-known/openid-configuration   discovery
//!   GET  /authorize                          authorization_code + PKCE (login + consent gated)
//!   POST /authorize/consent                  consent decision → issue code
//!   POST /oauth/token (code | refresh)       token endpoint (dispatched from manage::oauth_token)
//!   GET  /userinfo                           OP access-token → profile
//!   POST /oauth/introspect                   token introspection (RFC 7662)
//!   POST /oauth/revoke                       token revocation (RFC 7009)
//!   GET  /end_session                        RP-initiated logout (OIDC)
//!
//! id/access tokens are signed with the OP RS256 key (Phase 3a); the public half
//! is at /.well-known/jwks.json. The access token deliberately omits `aud` so
//! the internal RS256 verifier (which has no expected audience) accepts it; the
//! id_token carries `aud=client_id` for the relying party to check.

use axum::extract::{Form, Query, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{clear_session_cookie, require_session};
use crate::state::AppState;
use volta_auth_core::crypto::{random_token_hex, sha256_base64url, sha256_hex};
use volta_auth_core::jwt::JwtVerifier;
use volta_auth_core::record::{AuthzCodeRecord, OAuthClientRecord, RefreshTokenRecord};
use volta_auth_core::store::*;

const CODE_TTL_SECS: i64 = 120;
const AT_TTL_SECS: u64 = 3600;
const RT_TTL_DAYS: i64 = 30;

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}
/// Percent-encode a query value (chars outside the unreserved set).
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
fn scope_has(scope: &str, want: &str) -> bool {
    scope.split_whitespace().any(|s| s == want)
}

// ─── error responses ───────────────────────────────────────

/// OAuth token-endpoint error (JSON, per RFC 6749 §5.2).
fn oauth_err(status: StatusCode, error: &str, desc: &str) -> Response {
    let mut resp = (status, Json(json!({ "error": error, "error_description": desc }))).into_response();
    no_cache_headers(&mut resp);
    resp
}
/// Front-channel error rendered as a page (used before we can trust redirect_uri).
fn page_err(status: StatusCode, error: &str, desc: &str) -> Response {
    let body = format!("<!DOCTYPE html><html lang=\"ja\"><meta charset=\"utf-8\"><body style=\"font-family:system-ui;max-width:520px;margin:64px auto;padding:0 16px\"><h1>認可エラー</h1><p><code>{}</code></p><p>{}</p></body></html>",
        html_escape(error), html_escape(desc));
    let mut resp = (status, Html(body)).into_response();
    no_cache_headers(&mut resp);
    resp
}
/// Append `code`/`error` + `state` to a validated redirect_uri and 302 there.
fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let mut url = redirect_uri.to_string();
    let mut sep = if url.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        url.push(sep);
        url.push_str(&format!("{}={}", k, pct(v)));
        sep = '&';
    }
    let mut resp = Redirect::to(&url).into_response();
    no_cache_headers(&mut resp);
    resp
}

// ─── discovery ─────────────────────────────────────────────

pub async fn discovery(State(s): State<AppState>) -> Response {
    let b = &s.base_url;
    Json(json!({
        "issuer": b,
        "authorization_endpoint": format!("{b}/authorize"),
        "token_endpoint": format!("{b}/oauth/token"),
        "userinfo_endpoint": format!("{b}/userinfo"),
        "jwks_uri": format!("{b}/.well-known/jwks.json"),
        "device_authorization_endpoint": format!("{b}/oauth/device_authorization"),
        "end_session_endpoint": format!("{b}/end_session"),
        "introspection_endpoint": format!("{b}/oauth/introspect"),
        "revocation_endpoint": format!("{b}/oauth/revoke"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code","refresh_token","client_credentials","urn:ietf:params:oauth:grant-type:device_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post","none"],
        "scopes_supported": ["openid","email","profile","offline_access"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "claims_supported": ["sub","iss","aud","exp","iat","nonce","email","email_verified","name"],
    })).into_response()
}

// ─── authorize ─────────────────────────────────────────────

#[derive(Deserialize, Clone)]
pub struct AuthorizeQuery {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
}

pub async fn authorize(
    State(s): State<AppState>,
    jar: CookieJar,
    Query(q): Query<AuthorizeQuery>,
    RawQuery(raw): RawQuery,
) -> Response {
    // Validate client + redirect_uri BEFORE trusting them for redirects.
    let client_id = match q.client_id.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return page_err(StatusCode::BAD_REQUEST, "invalid_request", "client_id is required"),
    };
    let client = match OAuthClientStore::find_client(&s.db, &client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return page_err(StatusCode::BAD_REQUEST, "invalid_client", "unknown client_id"),
        Err(e) => return page_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string()),
    };
    let redirect_uri = match q.redirect_uri.as_deref() {
        Some(r) if client.allows_redirect(r) => r.to_string(),
        _ => return page_err(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uri is not registered for this client"),
    };
    let state = q.state.as_deref().unwrap_or("");

    // From here errors go back to the (validated) redirect_uri.
    if q.response_type.as_deref() != Some("code") {
        return redirect_with(&redirect_uri, &[("error", "unsupported_response_type"), ("state", state)]);
    }
    let (code_challenge, ccm) = match (q.code_challenge.as_deref(), q.code_challenge_method.as_deref()) {
        (Some(c), Some("S256")) if !c.is_empty() => (c.to_string(), "S256".to_string()),
        // PKCE S256 is mandatory (public & confidential alike).
        _ => return redirect_with(&redirect_uri, &[("error", "invalid_request"), ("error_description", "PKCE S256 required"), ("state", state)]),
    };
    let prompt = q.prompt.as_deref().unwrap_or("");
    let scope = q.scope.clone().unwrap_or_else(|| "openid".into());

    // Require an authenticated session.
    let session = match require_session(&s, &jar).await {
        Ok(sess) => sess,
        Err(_) => {
            if prompt == "none" {
                return redirect_with(&redirect_uri, &[("error", "login_required"), ("state", state)]);
            }
            let here = format!("{}/authorize?{}", s.base_url, raw.unwrap_or_default());
            let mut resp = Redirect::to(&format!("{}/login?return_to={}", s.base_url, pct(&here))).into_response();
            no_cache_headers(&mut resp);
            return resp;
        }
    };
    let user_id: Uuid = match session.user_id.parse() { Ok(u) => u, Err(_) => return redirect_with(&redirect_uri, &[("error", "server_error"), ("state", state)]) };
    let tenant_id: Uuid = session.tenant_id.parse().unwrap_or_default();

    // Consent (remembered, unless prompt=consent forces it).
    let consented = OAuthConsentStore::has_consent(&s.db, user_id, &client_id, &scope).await.unwrap_or(false);
    if prompt == "consent" || !consented {
        if prompt == "none" {
            return redirect_with(&redirect_uri, &[("error", "consent_required"), ("state", state)]);
        }
        return consent_screen(&client, &scope, &redirect_uri, &q, &code_challenge, &ccm);
    }

    issue_code(&s, &client_id, user_id, tenant_id, &redirect_uri, &scope, q.nonce.as_deref(), &code_challenge, &ccm, state).await
}

fn consent_screen(client: &OAuthClientRecord, scope: &str, redirect_uri: &str, q: &AuthorizeQuery, code_challenge: &str, ccm: &str) -> Response {
    let hidden = |k: &str, v: &str| format!("<input type=\"hidden\" name=\"{}\" value=\"{}\">", k, html_escape(v));
    let scope_items: String = scope.split_whitespace().map(|sc| {
        let label = match sc { "openid" => "サインイン", "email" => "メールアドレス", "profile" => "プロフィール(名前)", "offline_access" => "オフラインアクセス(継続ログイン)", other => other };
        format!("<li>{}</li>", html_escape(label))
    }).collect();
    let fields = format!("{}{}{}{}{}{}",
        hidden("client_id", &client.client_id),
        hidden("redirect_uri", redirect_uri),
        hidden("scope", scope),
        hidden("state", q.state.as_deref().unwrap_or("")),
        hidden("nonce", q.nonce.as_deref().unwrap_or("")),
        format!("{}{}", hidden("code_challenge", code_challenge), hidden("code_challenge_method", ccm)),
    );
    let html = CONSENT_HTML
        .replace("__CLIENT__", &html_escape(&client.name))
        .replace("__SCOPES__", &scope_items)
        .replace("__FIELDS__", &fields);
    let mut resp = Html(html).into_response();
    no_cache_headers(&mut resp);
    resp
}

#[derive(Deserialize)]
pub struct ConsentForm {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub decision: String, // "allow" | "deny"
}

pub async fn authorize_consent(State(s): State<AppState>, jar: CookieJar, Form(f): Form<ConsentForm>) -> Response {
    let session = match require_session(&s, &jar).await {
        Ok(sess) => sess,
        Err(_) => {
            let mut resp = Redirect::to(&format!("{}/login", s.base_url)).into_response();
            no_cache_headers(&mut resp);
            return resp;
        }
    };
    let client = match OAuthClientStore::find_client(&s.db, &f.client_id).await {
        Ok(Some(c)) if c.allows_redirect(&f.redirect_uri) => c,
        _ => return page_err(StatusCode::BAD_REQUEST, "invalid_request", "invalid client/redirect"),
    };
    let _ = client;
    let state = f.state.as_deref().unwrap_or("");
    if f.decision != "allow" {
        return redirect_with(&f.redirect_uri, &[("error", "access_denied"), ("state", state)]);
    }
    let user_id: Uuid = match session.user_id.parse() { Ok(u) => u, Err(_) => return redirect_with(&f.redirect_uri, &[("error", "server_error"), ("state", state)]) };
    let tenant_id: Uuid = session.tenant_id.parse().unwrap_or_default();
    let _ = OAuthConsentStore::grant_consent(&s.db, user_id, &f.client_id, &f.scope).await;
    issue_code(&s, &f.client_id, user_id, tenant_id, &f.redirect_uri, &f.scope, f.nonce.as_deref().filter(|n| !n.is_empty()), &f.code_challenge, &f.code_challenge_method, state).await
}

#[allow(clippy::too_many_arguments)]
async fn issue_code(s: &AppState, client_id: &str, user_id: Uuid, tenant_id: Uuid, redirect_uri: &str, scope: &str, nonce: Option<&str>, code_challenge: &str, ccm: &str, state: &str) -> Response {
    let code = random_token_hex(32);
    let rec = AuthzCodeRecord {
        code_hash: sha256_hex(&code),
        client_id: client_id.to_string(),
        user_id, tenant_id,
        redirect_uri: redirect_uri.to_string(),
        scope: scope.to_string(),
        nonce: nonce.map(String::from),
        code_challenge: Some(code_challenge.to_string()),
        code_challenge_method: Some(ccm.to_string()),
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(CODE_TTL_SECS),
        consumed_at: None,
        created_at: chrono::Utc::now(),
    };
    if let Err(e) = AuthzCodeStore::save_code(&s.db, rec).await {
        return redirect_with(redirect_uri, &[("error", "server_error"), ("error_description", &e.to_string()), ("state", state)]);
    }
    let mut params = vec![("code", code.as_str())];
    if !state.is_empty() { params.push(("state", state)); }
    redirect_with(redirect_uri, &params)
}

// ─── token endpoint grants (called from manage::oauth_token) ───

fn authenticate_client(client: &OAuthClientRecord, secret: Option<&str>) -> bool {
    match &client.client_secret_hash {
        Some(hash) => match secret {
            Some(s) => crate::security::constant_time_eq(sha256_hex(s).as_bytes(), hash.as_bytes()),
            None => false,
        },
        None => true, // public client — authenticated by PKCE instead
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn token_authorization_code(s: &AppState, client_id: &str, client_secret: Option<&str>, code: &str, redirect_uri: &str, code_verifier: Option<&str>) -> Response {
    let client = match OAuthClientStore::find_client(&s.db, client_id).await {
        Ok(Some(c)) => c,
        _ => return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"),
    };
    if !authenticate_client(&client, client_secret) {
        return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    }
    if !client.allows_grant("authorization_code") {
        return oauth_err(StatusCode::BAD_REQUEST, "unauthorized_client", "grant not allowed");
    }
    let rec = match AuthzCodeStore::consume_code(&s.db, &sha256_hex(code)).await {
        Ok(Some(r)) => r,
        Ok(None) => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code invalid, expired or already used"),
        Err(e) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string()),
    };
    if rec.client_id != client_id || rec.redirect_uri != redirect_uri {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code/redirect_uri mismatch");
    }
    // PKCE S256 verification.
    match (rec.code_challenge.as_deref(), rec.code_challenge_method.as_deref()) {
        (Some(challenge), Some("S256")) => {
            let verifier = match code_verifier { Some(v) if !v.is_empty() => v, _ => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code_verifier required") };
            if &sha256_base64url(verifier) != challenge {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
            }
        }
        _ => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "missing PKCE challenge"),
    }
    issue_tokens(s, &client, rec.user_id, rec.tenant_id, &rec.scope, rec.nonce.as_deref(), None).await
}

pub async fn token_refresh(s: &AppState, client_id: &str, client_secret: Option<&str>, refresh_token: &str) -> Response {
    let client = match OAuthClientStore::find_client(&s.db, client_id).await {
        Ok(Some(c)) => c,
        _ => return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"),
    };
    if !authenticate_client(&client, client_secret) {
        return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    }
    match RefreshTokenStore::rotate_refresh(&s.db, &sha256_hex(refresh_token)).await {
        Ok(RefreshOutcome::Rotated(old)) => {
            if old.client_id != client_id {
                return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "client mismatch");
            }
            issue_tokens(s, &client, old.user_id, old.tenant_id, &old.scope, None, Some(old.family_id)).await
        }
        Ok(RefreshOutcome::Reused) => oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token reuse detected — session revoked"),
        Ok(RefreshOutcome::Expired) => oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "refresh token expired"),
        Ok(RefreshOutcome::NotFound) => oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown refresh token"),
        Err(e) => oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string()),
    }
}

/// Mint access (+ id, + rotating refresh) tokens. `family` = Some for a refresh
/// rotation (continue the family), None for a fresh authorization_code grant.
async fn issue_tokens(s: &AppState, client: &OAuthClientRecord, user_id: Uuid, tenant_id: Uuid, scope: &str, nonce: Option<&str>, family: Option<Uuid>) -> Response {
    let Some(op) = &s.op_issuer else {
        return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "OP signing key unavailable");
    };
    let user = UserStore::find_by_id(&s.db, user_id).await.ok().flatten();
    let now = now_unix();
    let sub = user_id.to_string();

    // Access token: no `aud` (so the internal RS256 verifier at /userinfo accepts it).
    let access_claims = json!({
        "iss": s.base_url, "sub": sub, "scope": scope, "client_id": client.client_id,
        "iat": now, "exp": now + AT_TTL_SECS, "token_use": "access",
    });
    let access_token = match op.sign(&access_claims) {
        Ok(t) => t,
        Err(e) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string()),
    };

    let mut body = json!({
        "access_token": access_token, "token_type": "Bearer",
        "expires_in": AT_TTL_SECS, "scope": scope,
    });

    if scope_has(scope, "openid") {
        let mut idc = json!({
            "iss": s.base_url, "sub": sub, "aud": client.client_id,
            "iat": now, "exp": now + AT_TTL_SECS, "auth_time": now,
        });
        if let Some(n) = nonce { idc["nonce"] = json!(n); }
        if let Some(u) = &user {
            idc["email"] = json!(u.email);
            idc["email_verified"] = json!(true);
            if let Some(name) = &u.display_name { idc["name"] = json!(name); }
        }
        match op.sign(&idc) {
            Ok(t) => { body["id_token"] = json!(t); }
            Err(e) => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e.to_string()),
        }
    }

    // Refresh token (rotation) when the client is allowed offline access.
    if client.allows_grant("refresh_token") {
        let rt = random_token_hex(32);
        let family_id = family.unwrap_or_else(Uuid::new_v4);
        let rec = RefreshTokenRecord {
            token_hash: sha256_hex(&rt), family_id,
            client_id: client.client_id.clone(), user_id, tenant_id,
            scope: scope.to_string(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(RT_TTL_DAYS),
            revoked_at: None, created_at: chrono::Utc::now(),
        };
        if RefreshTokenStore::save_refresh(&s.db, rec).await.is_ok() {
            body["refresh_token"] = json!(rt);
        }
    }

    let mut resp = Json(body).into_response();
    no_cache_headers(&mut resp);
    resp
}

// ─── userinfo ──────────────────────────────────────────────

fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") { Some(token.trim().to_string()) } else { None }
}

/// Build a verifier from the active OP public key.
async fn op_verifier(s: &AppState) -> Option<JwtVerifier> {
    let key = SigningKeyStore::load_active(&s.db).await.ok().flatten()?;
    JwtVerifier::new_rsa(key.public_key.as_bytes()).ok()
}

pub async fn userinfo(State(s): State<AppState>, headers: HeaderMap) -> Response {
    let token = match bearer(&headers) {
        Some(t) => t,
        None => return oauth_err(StatusCode::UNAUTHORIZED, "invalid_token", "missing bearer token"),
    };
    let verifier = match op_verifier(&s).await {
        Some(v) => v,
        None => return oauth_err(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "no OP key"),
    };
    let claims = match verifier.verify(&token) {
        Ok(c) => c,
        Err(_) => return oauth_err(StatusCode::UNAUTHORIZED, "invalid_token", "token invalid or expired"),
    };
    let user_id: Uuid = match claims.sub.parse() { Ok(u) => u, Err(_) => return oauth_err(StatusCode::UNAUTHORIZED, "invalid_token", "bad subject") };
    let user = UserStore::find_by_id(&s.db, user_id).await.ok().flatten();
    let mut out = json!({ "sub": claims.sub });
    if let Some(u) = user {
        out["email"] = json!(u.email);
        out["email_verified"] = json!(true);
        if let Some(name) = u.display_name { out["name"] = json!(name); }
    }
    let mut resp = Json(out).into_response();
    no_cache_headers(&mut resp);
    resp
}

// ─── introspection (RFC 7662) + revocation (RFC 7009) ──────

#[derive(Deserialize)]
pub struct IntrospectForm {
    pub token: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

pub async fn introspect(State(s): State<AppState>, Form(f): Form<IntrospectForm>) -> Response {
    // Require valid client credentials to introspect.
    if let Some(cid) = f.client_id.as_deref() {
        match OAuthClientStore::find_client(&s.db, cid).await {
            Ok(Some(c)) if authenticate_client(&c, f.client_secret.as_deref()) => {}
            _ => return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client", "client auth failed"),
        }
    } else {
        return oauth_err(StatusCode::UNAUTHORIZED, "invalid_client", "client_id required");
    }
    let inactive = || { let mut r = Json(json!({ "active": false })).into_response(); no_cache_headers(&mut r); r };
    let verifier = match op_verifier(&s).await { Some(v) => v, None => return inactive() };
    match verifier.verify(&f.token) {
        Ok(c) => {
            let mut r = Json(json!({ "active": true, "sub": c.sub, "token_type": "Bearer" })).into_response();
            no_cache_headers(&mut r);
            r
        }
        Err(_) => inactive(),
    }
}

#[derive(Deserialize)]
pub struct RevokeForm {
    pub token: String,
    #[allow(dead_code)]
    pub token_type_hint: Option<String>,
}

pub async fn revoke(State(s): State<AppState>, Form(f): Form<RevokeForm>) -> Response {
    // Refresh tokens are stored by hash → revocable. Access tokens are stateless
    // JWTs and expire on their own; per RFC 7009 the endpoint still returns 200.
    let _ = RefreshTokenStore::revoke_refresh(&s.db, &sha256_hex(&f.token)).await;
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    no_cache_headers(&mut resp);
    resp
}

// ─── RP-initiated logout (OIDC end_session) ────────────────

#[derive(Deserialize)]
pub struct EndSessionQuery {
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    #[allow(dead_code)]
    pub id_token_hint: Option<String>,
}

pub async fn end_session(State(s): State<AppState>, Query(q): Query<EndSessionQuery>) -> Response {
    // Clear the active session cookie. Only honour a post-logout redirect that
    // is same-origin as the OP (avoid open redirects; per-client registration
    // of post_logout_redirect_uris is a later refinement).
    let target = match q.post_logout_redirect_uri {
        Some(uri) if uri.starts_with(&s.base_url) => {
            match q.state { Some(st) if !st.is_empty() => format!("{}{}state={}", uri, if uri.contains('?') { '&' } else { '?' }, pct(&st)), _ => uri }
        }
        _ => format!("{}/login", s.base_url),
    };
    let mut resp = Redirect::to(&target).into_response();
    clear_session_cookie(&mut resp, &s);
    no_cache_headers(&mut resp);
    resp
}

// ─── client registration (admin) ──────────────────────────

#[derive(Deserialize)]
pub struct CreateClientReq {
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// true → confidential (a client_secret is generated and returned once).
    #[serde(default)]
    pub confidential: bool,
}

pub async fn create_client(State(s): State<AppState>, jar: CookieJar, Json(b): Json<CreateClientReq>) -> Result<Response, ApiError> {
    crate::helpers::require_admin(&s, &jar).await?;
    let client_id = format!("volta-{}", &Uuid::new_v4().simple().to_string()[..16]);
    let (secret, secret_hash) = if b.confidential {
        let sec = random_token_hex(32);
        (Some(sec.clone()), Some(sha256_hex(&sec)))
    } else { (None, None) };
    let scopes = if b.scopes.is_empty() { vec!["openid".into(), "email".into(), "profile".into()] } else { b.scopes };
    let grant_types = if b.grant_types.is_empty() { vec!["authorization_code".into(), "refresh_token".into()] } else { b.grant_types };
    let rec = OAuthClientRecord {
        id: Uuid::new_v4(), client_id: client_id.clone(), client_secret_hash: secret_hash,
        name: b.name, redirect_uris: b.redirect_uris, grant_types, scopes,
        is_confidential: b.confidential, created_at: chrono::Utc::now(),
    };
    OAuthClientStore::create_client(&s.db, rec).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    // client_secret is shown exactly once.
    Ok(Json(json!({ "client_id": client_id, "client_secret": secret })).into_response())
}

pub async fn list_clients(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    crate::helpers::require_admin(&s, &jar).await?;
    let clients = OAuthClientStore::list_clients(&s.db).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<_> = clients.into_iter().map(|c| json!({
        "client_id": c.client_id, "name": c.name, "redirect_uris": c.redirect_uris,
        "scopes": c.scopes, "grant_types": c.grant_types, "confidential": c.is_confidential,
        "created_at": c.created_at.to_rfc3339(),
    })).collect();
    Ok(Json(json!({ "clients": items })).into_response())
}

const CONSENT_HTML: &str = r##"<!DOCTYPE html><html lang="ja"><head>
<meta charset="utf-8"><title>アクセスの許可 — volta</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);max-width:420px;width:100%;padding:28px}
h1{font-size:18px;margin:0 0 6px}
p{color:#555;font-size:14px;margin:0 0 14px}
ul{background:#f7f9ff;border:1px solid #e2e8ff;border-radius:8px;padding:12px 12px 12px 30px;margin:0 0 20px}
li{margin:4px 0;font-size:14px}
.row{display:flex;gap:10px}
button{flex:1;padding:12px;border:0;border-radius:8px;font-size:15px;cursor:pointer}
.allow{background:#0f3460;color:#fff}.allow:hover{background:#16213e}
.deny{background:#eee;color:#444}.deny:hover{background:#e0e0e0}
</style></head><body>
<div class="card">
  <h1><b>__CLIENT__</b> がアクセスを求めています</h1>
  <p>次の権限を許可しますか？</p>
  <ul>__SCOPES__</ul>
  <form method="post" action="/authorize/consent">
    __FIELDS__
    <div class="row">
      <button class="allow" name="decision" value="allow" type="submit">許可する</button>
      <button class="deny" name="decision" value="deny" type="submit">拒否</button>
    </div>
  </form>
</div>
</body></html>"##;
