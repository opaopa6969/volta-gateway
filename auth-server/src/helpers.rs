//! Shared helpers — cookie handling, state signing, content negotiation.

use axum::http::HeaderMap;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ApiError;
use crate::state::AppState;
use volta_auth_core::record::SessionRecord;
use volta_auth_core::store::SessionStore;

type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "__volta_session";

/// Resolve the current session from the request cookie, or return 401.
///
/// Shared by all non-public handlers.
pub async fn require_session(state: &AppState, jar: &CookieJar) -> Result<SessionRecord, ApiError> {
    let sid = extract_session_id(jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    SessionStore::find(&state.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))
}

/// #9 + backlog P0 #3: require ADMIN/OWNER privilege, accepting either a
/// cookie session **or** a `Authorization: Bearer <jwt>` token.
///
/// Precedence:
/// 1. If `Authorization: Bearer` is present, the JWT decides — no cookie
///    fallback. Missing/invalid role → 403; invalid/expired token → 401.
/// 2. Otherwise fall back to cookie session check.
///
/// See `auth-server/docs/specs/bearer-m2m-scope.md`.
pub async fn require_admin(state: &AppState, jar: &CookieJar) -> Result<SessionRecord, ApiError> {
    require_admin_with_headers(state, jar, None).await
}

/// Variant used by handlers that already have `HeaderMap` in scope. When a
/// Bearer token is presented, cookie session is ignored.
pub async fn require_admin_with_headers(
    state: &AppState,
    jar: &CookieJar,
    headers: Option<&axum::http::HeaderMap>,
) -> Result<SessionRecord, ApiError> {
    if let Some(h) = headers {
        if let Some(token) = bearer_token(h) {
            return bearer_admin(state, token);
        }
    }
    let session = require_session(state, jar).await?;
    enforce_admin_role(&session.roles)?;
    Ok(session)
}

/// Pull the bearer value out of `Authorization: Bearer <jwt>`, returning
/// `None` when the header is missing or malformed.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer ").or_else(|| s.strip_prefix("bearer ")))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn bearer_admin(state: &AppState, token: &str) -> Result<SessionRecord, ApiError> {
    let claims = state
        .jwt_verifier
        .verify(token)
        .map_err(|_| ApiError::unauthorized("INVALID_TOKEN", "invalid or expired token"))?;
    let roles: Vec<String> = claims
        .roles
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    enforce_admin_role(&roles)?;
    Ok(synthetic_session_from_claims(claims, roles))
}

fn enforce_admin_role(roles: &[String]) -> Result<(), ApiError> {
    let is_privileged = roles.iter().any(|r| {
        let u = r.to_ascii_uppercase();
        u == "ADMIN" || u == "OWNER"
    });
    if !is_privileged {
        return Err(ApiError::forbidden(
            "INSUFFICIENT_SCOPE",
            "ADMIN or OWNER role required",
        ));
    }
    Ok(())
}

fn synthetic_session_from_claims(
    claims: volta_auth_core::jwt::VoltaClaims,
    roles: Vec<String>,
) -> SessionRecord {
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    SessionRecord {
        session_id: format!("m2m-{}", uuid::Uuid::new_v4()),
        user_id: claims.sub,
        tenant_id: claims.tenant_id.unwrap_or_default(),
        return_to: None,
        created_at: now_epoch,
        last_active_at: now_epoch,
        expires_at: claims.exp.unwrap_or(now_epoch + 300) as u64,
        invalidated_at: None,
        mfa_verified_at: Some(now_epoch), // M2M is not interactive — treat as MFA-equivalent
        ip_address: None,
        user_agent: None,
        csrf_token: None,
        email: claims.email,
        tenant_slug: claims.tenant_slug,
        roles,
        display_name: claims.name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn bearer_header_parses_both_cases() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer abc.def.ghi".parse().unwrap());
        assert_eq!(bearer_token(&h), Some("abc.def.ghi"));

        let mut h2 = HeaderMap::new();
        h2.insert("authorization", "bearer XYZ".parse().unwrap());
        assert_eq!(bearer_token(&h2), Some("XYZ"));
    }

    #[test]
    fn bearer_missing_returns_none() {
        let h = HeaderMap::new();
        assert!(bearer_token(&h).is_none());
    }

    #[test]
    fn bearer_wrong_scheme_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert!(bearer_token(&h).is_none());
    }

    #[test]
    fn bearer_empty_value_returns_none() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer   ".parse().unwrap());
        assert!(bearer_token(&h).is_none());
    }

    #[test]
    fn admin_role_enforced_case_insensitively() {
        enforce_admin_role(&["admin".into()]).unwrap();
        enforce_admin_role(&["Owner".into()]).unwrap();
        enforce_admin_role(&["OWNER".into()]).unwrap();
        assert!(enforce_admin_role(&["member".into()]).is_err());
        assert!(enforce_admin_role(&[]).is_err());
    }
}

/// Extract session ID from __volta_session cookie.
pub fn extract_session_id(jar: &CookieJar) -> Option<String> {
    jar.get(COOKIE_NAME).map(|c| c.value().to_string())
}

/// Set __volta_session cookie on response (Java compat format).
pub fn set_session_cookie(resp: &mut Response, session_id: &str, state: &AppState) {
    let mut cookie = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
        COOKIE_NAME, session_id, state.session_ttl_secs,
    );
    if !state.cookie_domain.is_empty() {
        cookie.push_str(&format!("; Domain={}", state.cookie_domain));
    }
    if state.force_secure_cookie {
        cookie.push_str("; Secure");
    }
    resp.headers_mut().append("set-cookie", cookie.parse().unwrap());
}

/// Clear __volta_session cookie.
///
/// Fix #11: includes `Secure` / `SameSite` / `HttpOnly` so the clearing cookie
/// has the same attributes as the original (required by Chrome/Firefox to
/// actually overwrite the stored cookie rather than leave a duplicate alive).
pub fn clear_session_cookie(resp: &mut Response, state: &AppState) {
    let mut cookie = format!(
        "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        COOKIE_NAME,
    );
    if !state.cookie_domain.is_empty() {
        cookie.push_str(&format!("; Domain={}", state.cookie_domain));
    }
    if state.force_secure_cookie {
        cookie.push_str("; Secure");
    }
    resp.headers_mut().append("set-cookie", cookie.parse().unwrap());
}

/// Check if Accept header wants JSON.
pub fn is_json_accept(headers: &HeaderMap) -> bool {
    headers.get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

/// Sign OIDC state parameter with HMAC-SHA256.
/// Format: `{flow_id}:{return_to}:{invite}:{hmac_hex}`
pub fn sign_state(flow_id: &str, return_to: &str, invite: Option<&str>, key: &[u8]) -> String {
    let invite_str = invite.unwrap_or("");
    let payload = format!("{}:{}:{}", flow_id, return_to, invite_str);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(payload.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("{}:{}", payload, sig)
}

/// Verify and decode OIDC state parameter.
/// Returns (flow_id, return_to, invite) if valid.
pub fn verify_state(state: &str, key: &[u8]) -> Option<(String, String, Option<String>)> {
    // Format: flow_id:return_to:invite:hmac_hex
    // return_to may contain colons (URLs), so split from the end
    let last_colon = state.rfind(':')?;
    let (payload, sig_hex) = state.split_at(last_colon);
    let sig_hex = &sig_hex[1..]; // skip the colon

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(payload.as_bytes());
    let expected = hex::decode(sig_hex).ok()?;
    mac.verify_slice(&expected).ok()?;

    // Parse payload: flow_id:return_to:invite
    // flow_id is a UUID (no colons), invite may be empty
    // return_to can contain colons, so split carefully
    let mut parts = payload.splitn(2, ':');
    let flow_id = parts.next()?.to_string();
    let rest = parts.next()?;

    // rest = return_to:invite — invite is the part after the last colon if it looks like an invite code
    // But return_to can contain colons. Use a different separator approach:
    // Actually the format should be: flow_id:return_to_base64:invite:hmac
    // Let's use a simpler approach: the last segment before hmac is invite (may be empty)
    let last_colon_in_rest = rest.rfind(':');
    match last_colon_in_rest {
        Some(pos) => {
            let return_to = rest[..pos].to_string();
            let invite_str = &rest[pos+1..];
            let invite = if invite_str.is_empty() { None } else { Some(invite_str.to_string()) };
            Some((flow_id, return_to, invite))
        }
        None => {
            // No invite
            Some((flow_id, rest.to_string(), None))
        }
    }
}
