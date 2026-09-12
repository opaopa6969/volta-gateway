//! Session management handlers.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{extract_session_id, set_session_cookie};
use crate::state::AppState;
use volta_auth_core::crypto::session_id_fingerprint;
use volta_auth_core::store::SessionStore;

/// POST /auth/session/keepalive — ttyd 接続中の明示的なセッション延長。
/// Cookie の Max-Age も更新する。通常の認証確認や JWT 発行とは独立させる。
pub async fn keepalive(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let sid = renew_session(&state.db, &headers, &jar, state.session_ttl_secs).await?;
    let mut resp = Json(serde_json::json!({"expiresIn": state.session_ttl_secs})).into_response();
    set_session_cookie(&mut resp, &sid, &state);
    no_cache_headers(&mut resp);
    Ok(resp)
}

async fn renew_session(
    store: &impl SessionStore,
    headers: &HeaderMap,
    jar: &CookieJar,
    ttl: u64,
) -> Result<String, ApiError> {
    // CORS を許可しない endpoint。cross-origin form POST では送れないヘッダを要求。
    // index は同一 origin を確認してから Cookie とこのヘッダだけを転送する。
    if headers
        .get("x-volta-session-keepalive")
        .and_then(|h| h.to_str().ok())
        != Some("1")
    {
        return Err(ApiError::forbidden(
            "KEEPALIVE_HEADER_REQUIRED",
            "explicit session renewal required",
        ));
    }
    let expired = || ApiError::unauthorized("SESSION_EXPIRED", "re-login");
    let sid = extract_session_id(jar).ok_or_else(expired)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .as_secs();
    // touch は存在・有効期限・失効状態の確認と更新を原子的に行う。
    store
        .touch(&sid, now.saturating_add(ttl))
        .await
        .map_err(|e| match e {
            volta_auth_core::error::AuthError::SessionNotFound => expired(),
            _ => ApiError::internal(&e.to_string()),
        })?;
    Ok(sid)
}

/// GET /api/me/sessions — list user's active sessions.
pub async fn list_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar).ok_or_else(|| {
        ApiError::unauthorized(
            "SESSION_EXPIRED",
            "セッションの有効期限が切れました。再ログインしてください。",
        )
    })?;

    let session = SessionStore::find(&state.db, &session_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| {
            ApiError::unauthorized(
                "SESSION_EXPIRED",
                "セッションの有効期限が切れました。再ログインしてください。",
            )
        })?;

    let sessions = SessionStore::list_by_user(&state.db, &session.user_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let items: Vec<serde_json::Value> = sessions
        .iter()
        .map(|s| {
            serde_json::json!({
                "session_id_hash": session_id_fingerprint(&s.session_id),
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "created_at": s.created_at,
                "last_active_at": s.last_active_at,
                "current": s.session_id == session_id,
            })
        })
        .collect();

    Ok(Json(items).into_response())
}

/// DELETE /api/me/sessions/{id} — revoke a specific session.
pub async fn revoke_session(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(target_id): Path<String>,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar).ok_or_else(|| {
        ApiError::unauthorized(
            "SESSION_EXPIRED",
            "セッションの有効期限が切れました。再ログインしてください。",
        )
    })?;

    // Verify caller is authenticated
    let _session = SessionStore::find(&state.db, &session_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| {
            ApiError::unauthorized(
                "SESSION_EXPIRED",
                "セッションの有効期限が切れました。再ログインしてください。",
            )
        })?;

    let target = SessionStore::list_by_user(&state.db, &_session.user_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .into_iter()
        .find(|s| s.session_id == target_id || session_id_fingerprint(&s.session_id) == target_id)
        .ok_or_else(|| ApiError::bad_request("SESSION_NOT_FOUND", "session not found"))?;

    SessionStore::revoke(&state.db, &target.session_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"ok": true})).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

/// DELETE /api/me/sessions — revoke all sessions for user.
pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session_id = extract_session_id(&jar).ok_or_else(|| {
        ApiError::unauthorized(
            "SESSION_EXPIRED",
            "セッションの有効期限が切れました。再ログインしてください。",
        )
    })?;

    let session = SessionStore::find(&state.db, &session_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| {
            ApiError::unauthorized(
                "SESSION_EXPIRED",
                "セッションの有効期限が切れました。再ログインしてください。",
            )
        })?;

    let count = SessionStore::revoke_all_for_user(&state.db, &session.user_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"ok": true, "revoked": count})).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[cfg(test)]
mod keepalive_tests {
    use super::*;
    use axum::http::StatusCode;
    use axum_extra::extract::cookie::Cookie;
    use volta_auth_core::record::SessionRecord;
    use volta_auth_core::store::InMemorySessionStore;

    fn session(id: &str, expires_at: u64) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            user_id: "user".into(),
            tenant_id: "tenant".into(),
            return_to: None,
            created_at: 1,
            last_active_at: 1,
            expires_at,
            invalidated_at: None,
            mfa_verified_at: None,
            ip_address: None,
            user_agent: None,
            csrf_token: None,
            email: None,
            tenant_slug: None,
            roles: vec!["VIEWER".into()],
            display_name: None,
        }
    }
    fn now() -> u64 {
        chrono::Utc::now().timestamp() as u64
    }
    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-volta-session-keepalive", "1".parse().unwrap());
        headers
    }
    fn jar(id: &str) -> CookieJar {
        CookieJar::new().add(Cookie::new("__volta_session", id.to_string()))
    }

    #[tokio::test]
    async fn renews_only_requested_session_without_changing_identity() {
        let store = InMemorySessionStore::new();
        store.create(session("active", now() + 20)).await.unwrap();
        store.create(session("other", now() + 20)).await.unwrap();
        let other = store.find("other").await.unwrap().unwrap().expires_at;
        let before = now();
        assert_eq!(
            renew_session(&store, &headers(), &jar("active"), 28800)
                .await
                .unwrap(),
            "active"
        );
        let active = store.find("active").await.unwrap().unwrap();
        assert!(active.expires_at >= before + 28800);
        assert!(active.last_active_at >= before);
        assert_eq!(active.roles, vec!["VIEWER"]);
        assert!(active.mfa_verified_at.is_none());
        assert_eq!(
            store.find("other").await.unwrap().unwrap().expires_at,
            other
        );
    }

    #[tokio::test]
    async fn expired_revoked_missing_and_anonymous_sessions_cannot_renew() {
        let store = InMemorySessionStore::new();
        store.create(session("expired", now() - 1)).await.unwrap();
        store.create(session("revoked", now() + 20)).await.unwrap();
        store.revoke("revoked").await.unwrap();
        for cookies in [
            jar("expired"),
            jar("revoked"),
            jar("missing"),
            CookieJar::new(),
        ] {
            let error = renew_session(&store, &headers(), &cookies, 28800)
                .await
                .unwrap_err();
            assert_eq!(error.status, StatusCode::UNAUTHORIZED);
        }
        assert!(store.find("expired").await.unwrap().is_none());
        assert!(store.find("revoked").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn form_post_cannot_extend_a_session() {
        let store = InMemorySessionStore::new();
        let expires = now() + 20;
        store.create(session("active", expires)).await.unwrap();
        let error = renew_session(&store, &HeaderMap::new(), &jar("active"), 28800)
            .await
            .unwrap_err();
        assert_eq!(error.status, StatusCode::FORBIDDEN);
        assert_eq!(
            store.find("active").await.unwrap().unwrap().expires_at,
            expires
        );
    }
}
