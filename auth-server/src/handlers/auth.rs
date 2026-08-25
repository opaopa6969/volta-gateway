//! /auth/* handlers — verify, logout, refresh, switch-tenant.
//! 100% compatible with Java volta-auth-proxy.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::auth_events::AuthEvent;
use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{
    clear_session_cookie, extract_session_id, is_json_accept, set_session_cookie,
};
use crate::local_bypass::PeerIp;
use crate::state::AppState;
use volta_auth_core::store::{
    MembershipStore, MfaStore, PasskeyStore, SessionStepUpStore, SessionStore, TenantStore,
};

/// Publish a `LOGOUT` auth event for `/viz/auth/stream` (P1.2) and persist
/// it to `audit_logs` (P2 #10). Session lookup is best-effort — a missing
/// session still produces an event (SSE clients filter by event_type).
async fn publish_logout_event(state: &AppState, session_id: &str) {
    let mut ev = AuthEvent::now("LOGOUT").with_session(session_id);
    if let Ok(Some(s)) = SessionStore::find(&state.db, session_id).await {
        ev = ev.with_user(s.user_id).with_tenant(s.tenant_id);
    }
    state
        .auth_events
        .publish_and_audit(
            ev,
            &state.db,
            None,
            Some("SESSION".into()),
            Some(session_id.to_string()),
            None,
        )
        .await;
}

/// GET /auth/verify — ForwardAuth endpoint for gateway.
///
/// Order mirrors Java `AuthFlowHandler.verify` (`99a2769` + `4006ee7`):
///   1. Require forwarded headers from the gateway.
///   2. If a session cookie is present → resolve session:
///       a. session invalid/expired → redirect to /login
///       b. MFA pending → 302 to /mfa/challenge
///       c. OK → 200 + `X-Volta-*` headers
///   3. No session → local-network bypass: if the caller's IP is LAN/Tailscale,
///      return 200 anonymous with `X-Volta-Auth-Source: local-bypass` (P1.3).
///   4. No session + external IP → redirect to /login.
///
/// The bypass only fires when there is no session so that authenticated LAN
/// users still get their real user headers and MFA enforcement.
pub async fn verify(
    State(state): State<AppState>,
    PeerIp(peer_ip): PeerIp,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let forwarded_host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok());
    let forwarded_uri = headers.get("x-forwarded-uri").and_then(|v| v.to_str().ok());
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");

    if forwarded_host.is_none() || forwarded_uri.is_none() {
        return ApiError::unauthorized("AUTHENTICATION_REQUIRED", "Missing forwarded headers")
            .into_response();
    }

    let redirect_to_login = || {
        let return_to = format!(
            "{}://{}{}",
            forwarded_proto,
            forwarded_host.unwrap(),
            forwarded_uri.unwrap()
        );
        let location = format!(
            "{}/login?return_to={}",
            state.base_url,
            urlencoding::encode(&return_to)
        );
        let mut resp = Redirect::to(&location).into_response();
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        no_cache_headers(&mut resp);
        resp
    };

    // ── Bearer path ───────────────────────────────────────────
    //
    // gateway も /auth/verify も Authorization を見ていなかったので、既存の
    // M2M / OIDC アクセストークンを持っていても **gateway 配下のサービスには
    // 入れなかった**。OAuth 一式が auth-server 自身の API 専用になっていた。
    //
    // **無効な Authorization でリクエストを落とさない。**
    // gateway 配下には、自分で Authorization を解釈するサービスがいる
    // （Basic 認証、独自の API キー等）。ここで「Volta の JWT でなければ 401」に
    // すると、**今まで動いていたサービスが一斉に壊れる**。
    // 検証に通ったときだけ認証済みとして扱い、それ以外は下の経路へ落とす。
    //
    // セッション cookie より後ろに置いてあるのも同じ理由で、既存の挙動を
    // 一切変えないため。両方付いている場合は cookie が勝つ。
    if let Some(token) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
        })
        .filter(|t| !t.is_empty())
    {
        match state.jwt_verifier.verify(&token) {
            Ok(claims) => {
                // aud があるなら、この host 向けに出された token か確かめる。
                //
                // 無いと **あるサービス向けに出した token が別サービスでも通る**。
                // aud を持たない古い token は従来どおり通す（後方互換）。
                let host = forwarded_host.unwrap_or("");
                if !claims.allows_audience(host) {
                    tracing::warn!(
                        host = %host,
                        aud = ?claims.aud,
                        "verify denied: bearer token audience mismatch"
                    );
                    let mut resp = StatusCode::FORBIDDEN.into_response();
                    resp.headers_mut()
                        .insert("x-volta-auth-reason", "audience_mismatch".parse().unwrap());
                    no_cache_headers(&mut resp);
                    return resp;
                }

                // 必要ロールの評価は cookie 経路と同じ規則にする。
                // ここを飛ばすと **Bearer なら min_role を無視して入れる**
                // 抜け道になる。
                if let Some(required) = headers
                    .get("x-volta-required-role")
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    let required = required.to_ascii_uppercase();
                    let roles: Vec<String> = claims
                        .roles
                        .as_deref()
                        .unwrap_or("")
                        .split(',')
                        .map(|r| r.trim().to_ascii_uppercase())
                        .filter(|r| !r.is_empty())
                        .collect();
                    let policy = volta_auth_core::policy::PolicyEngine::default_policy();
                    if let volta_auth_core::policy::PolicyResult::Deny(reason) =
                        policy.enforce_min_role(&roles, &required)
                    {
                        tracing::warn!(
                            sub = %claims.sub,
                            roles = ?roles,
                            required = %required,
                            reason = %reason,
                            "verify denied: bearer token role requirement not met"
                        );
                        let mut resp = StatusCode::FORBIDDEN.into_response();
                        let h = resp.headers_mut();
                        h.insert("x-volta-auth-reason", "insufficient_role".parse().unwrap());
                        if let Ok(v) = required.as_str().parse() {
                            h.insert("x-volta-required-role", v);
                        }
                        no_cache_headers(&mut resp);
                        return resp;
                    }
                }

                let mut resp = StatusCode::OK.into_response();
                let h = resp.headers_mut();
                for (k, v) in claims.to_volta_headers() {
                    if let (Ok(name), Ok(value)) = (
                        axum::http::HeaderName::try_from(k.as_str()),
                        v.parse::<axum::http::HeaderValue>(),
                    ) {
                        h.insert(name, value);
                    }
                }
                // backend が「素のログインではない」と分かるようにする。
                h.insert("x-volta-auth-source", "bearer".parse().unwrap());
                if let Some(ref jti) = claims.jti {
                    if let Ok(v) = jti.parse() {
                        h.insert("x-volta-token-id", v);
                    }
                }
                if let Some(ref scope) = claims.scope {
                    if let Ok(v) = scope.parse() {
                        h.insert("x-volta-scope", v);
                    }
                }
                no_cache_headers(&mut resp);
                return resp;
            }
            Err(e) => {
                // 落とさない。下の経路（cookie 済み / local bypass / login）へ。
                tracing::debug!(error = ?e, "bearer token not a valid volta JWT — falling through");
            }
        }
    }

    // ── Session path ──────────────────────────────────────────
    if let Some(session_id) = extract_session_id(&jar) {
        let session = match SessionStore::find(&state.db, &session_id).await {
            Ok(Some(s)) => s,
            _ => return redirect_to_login(),
        };

        // AUTH-010 step 4: tenant suspension (#94)
        //
        // SPEC §5.5 はこのステップを規定しているが実装が無く、**テナントを停止しても
        // 既存セッションはそのまま通り続けていた**（新規ログインだけが止まる）。
        // 停止の意味が「今すぐ使わせない」なら、既に持っているセッションも止める
        // 必要がある。
        //
        // SPEC は `suspended_at IS NOT NULL` と書いているが、実スキーマ
        // (`002_create_tenants.sql`) にその列は無く `is_active BOOLEAN` が正。
        // console の suspend/activate もこの列を反転する。SPEC 側を実態に合わせた。
        //
        // 403 を返すのは、ログインし直しても解決しない（テナントが停止している）
        // ため。302 で /login に送ると無限ループになる。
        // fail-open: テナントを引けなかった場合は通す。DB の一時障害で全ユーザーを
        // 締め出すより、停止テナントが一時的に通る方がまだ軽い。
        if let Ok(tenant_uuid) = session.tenant_id.parse::<uuid::Uuid>() {
            match TenantStore::find_by_id(&state.db, tenant_uuid).await {
                Ok(Some(tenant)) if !tenant.is_active => {
                    tracing::warn!(
                        tenant_id = %session.tenant_id,
                        user_id = %session.user_id,
                        "verify denied: tenant is suspended (is_active = false)"
                    );
                    let mut resp = StatusCode::FORBIDDEN.into_response();
                    resp.headers_mut()
                        .insert("x-volta-auth-reason", "tenant_suspended".parse().unwrap());
                    no_cache_headers(&mut resp);
                    return resp;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(
                        tenant_id = %session.tenant_id,
                        error = %e,
                        "tenant suspension check failed — allowing (fail-open)"
                    );
                }
            }
        }

        // #58 / volta-platform#41: ルートが要求する最低ロールを満たすか。
        //
        // gateway が `X-Volta-Required-Role` で「何が必要か」を渡してくる
        // （services.json の `access.minRole` 由来）。**判定をこちら側でやるのは、
        // ロールの正がセッションにあるため。** gateway に判定させると、gateway が
        // ロール階層を知る必要が出て二重管理になる。
        //
        // これまで minRole は services.json に書けるだけで**誰も読んでいなかった**。
        // 「operator 限定にしたつもり」でも viewer でログインすれば通っていた。
        //
        // 403 を返すのは、ログインし直しても足りないロールは満たせないため
        // （302 で /login に送ると無限ループになる）。
        if let Some(required) = headers
            .get("x-volta-required-role")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let policy = volta_auth_core::policy::PolicyEngine::default_policy();

            // 大文字小文字は正規化する。services.json には `operator` と
            // `OPERATOR` が混在している（schema がどちらも許してきた）。
            let required = required.to_ascii_uppercase();

            // `is_at_least` を直接使わないこと。未知のロールは rank が
            // usize::MAX になり `rank(user) <= MAX` が常に真 = **全員通る**。
            // enforce_min_role は未知ロールを拒否する（fail-closed）。
            let decision = policy.enforce_min_role(&session.roles, &required);
            if let volta_auth_core::policy::PolicyResult::Deny(reason) = decision {
                tracing::warn!(
                    user_id = %session.user_id,
                    roles = ?session.roles,
                    required = %required,
                    reason = %reason,
                    "verify denied: role requirement not met"
                );
                let mut resp = StatusCode::FORBIDDEN.into_response();
                let h = resp.headers_mut();
                h.insert("x-volta-auth-reason", "insufficient_role".parse().unwrap());
                // 何が足りないかを返す。画面側が「ADMIN が必要です」と出せる。
                if let Ok(v) = required.as_str().parse() {
                    h.insert("x-volta-required-role", v);
                }
                no_cache_headers(&mut resp);
                return resp;
            }
        }

        // P1.1 AUTH-010: MFA pending → send user to challenge (only if they are
        // not already navigating to the MFA page, to avoid redirect loops).
        // Only enforce when the user actually has an *active* second factor —
        // a fresh session always has mfa_verified_at = None, so without this
        // guard a user who never enrolled MFA would be bounced to the challenge
        // forever with no code to enter (lockout).
        if session.mfa_verified_at.is_none() {
            if let Some(uri) = forwarded_uri {
                let is_mfa_path = uri.starts_with("/mfa/") || uri.starts_with("/auth/mfa/");
                let uid = session.user_id.parse::<uuid::Uuid>().ok();
                let has_totp = match uid {
                    Some(u) => MfaStore::has_active(&state.db, u).await.unwrap_or(false),
                    None => false,
                };
                // Phase 4c risk step-up: a flagged session must present a second
                // factor even without a tenant MFA policy — and a passkey counts,
                // so passkey-only users are covered too. Unflagged sessions keep
                // the original TOTP-only behaviour exactly.
                let stepup_required =
                    SessionStepUpStore::is_required(&state.db, &session.session_id)
                        .await
                        .unwrap_or(false);
                let has_passkey = match (stepup_required, uid) {
                    (true, Some(u)) => PasskeyStore::list_by_user(&state.db, u)
                        .await
                        .map(|v| !v.is_empty())
                        .unwrap_or(false),
                    _ => false,
                };
                let needs_challenge = has_totp || (stepup_required && has_passkey);
                if !is_mfa_path && needs_challenge {
                    let location = format!("{}/mfa/challenge", state.base_url);
                    let mut resp = Redirect::to(&location).into_response();
                    *resp.status_mut() = StatusCode::UNAUTHORIZED;
                    no_cache_headers(&mut resp);
                    return resp;
                }
            }
        }

        // Build volta headers
        let mut resp = StatusCode::OK.into_response();
        let h = resp.headers_mut();
        h.insert("x-volta-user-id", session.user_id.parse().unwrap());
        if let Some(ref email) = session.email {
            h.insert("x-volta-email", email.parse().unwrap());
        }
        h.insert("x-volta-tenant-id", session.tenant_id.parse().unwrap());
        if let Some(ref slug) = session.tenant_slug {
            h.insert("x-volta-tenant-slug", slug.parse().unwrap());
        }
        if !session.roles.is_empty() {
            h.insert("x-volta-roles", session.roles.join(",").parse().unwrap());
        }
        let display = session.display_name.as_deref().unwrap_or("");
        h.insert("x-volta-display-name", display.parse().unwrap());

        if let Ok(jwt) = state.jwt_issuer.issue(&volta_auth_core::jwt::VoltaClaims {
            sub: session.user_id.clone(),
            email: session.email.clone(),
            tenant_id: Some(session.tenant_id.clone()),
            tenant_slug: session.tenant_slug.clone(),
            roles: if session.roles.is_empty() {
                None
            } else {
                Some(session.roles.join(","))
            },
            name: session.display_name.clone(),
            app_id: None,
            iat: None,
            exp: None,
            jti: None,
            aud: None,
            scope: None,
        }) {
            h.insert("x-volta-jwt", jwt.parse().unwrap());
        }

        no_cache_headers(&mut resp);
        return resp;
    }

    // ── No session: local-network bypass (P1.3) ───────────────
    if state.local_bypass.matches_request(&headers, peer_ip) {
        let mut resp = StatusCode::OK.into_response();
        resp.headers_mut()
            .insert("x-volta-auth-source", "local-bypass".parse().unwrap());
        no_cache_headers(&mut resp);
        return resp;
    }

    // ── External caller, no session → login ───────────────────
    redirect_to_login()
}

#[derive(Deserialize)]
pub struct LogoutQuery {
    pub return_to: Option<String>,
}

/// Only forward a `return_to` that points back at our own apps (https on
/// *.unlaxer.org) — avoids turning logout into an open redirect.
fn is_safe_return_to(rt: &str) -> bool {
    let Some(rest) = rt.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or("");
    host == "unlaxer.org" || host.ends_with(".unlaxer.org")
}

/// GET /auth/logout — browser logout with redirect. Honors a safe `return_to`
/// so logging out from an app (e.g. console) lands back at that app's login.
pub async fn logout_get(
    State(state): State<AppState>,
    Query(q): Query<LogoutQuery>,
    jar: CookieJar,
) -> Response {
    if let Some(session_id) = extract_session_id(&jar) {
        publish_logout_event(&state, &session_id).await;
        let _ = SessionStore::revoke(&state.db, &session_id).await;
    }
    let login = match q.return_to.as_deref().filter(|r| is_safe_return_to(r)) {
        Some(rt) => format!(
            "{}/login?return_to={}",
            state.base_url,
            urlencoding::encode(rt)
        ),
        None => format!("{}/login", state.base_url),
    };
    let mut resp = Redirect::to(&login).into_response();
    clear_session_cookie(&mut resp, &state);
    no_cache_headers(&mut resp);
    resp
}

/// POST /auth/logout — API logout.
pub async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    if let Some(session_id) = extract_session_id(&jar) {
        publish_logout_event(&state, &session_id).await;
        let _ = SessionStore::revoke(&state.db, &session_id).await;
    }

    if is_json_accept(&headers) {
        let mut resp = Json(serde_json::json!({"ok": true})).into_response();
        clear_session_cookie(&mut resp, &state);
        no_cache_headers(&mut resp);
        resp
    } else {
        let mut resp = Redirect::to("/login").into_response();
        clear_session_cookie(&mut resp, &state);
        no_cache_headers(&mut resp);
        resp
    }
}

/// POST /auth/refresh — get fresh JWT.
pub async fn refresh(State(state): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
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

    let jwt = state
        .jwt_issuer
        .issue(&volta_auth_core::jwt::VoltaClaims {
            sub: session.user_id,
            email: session.email,
            tenant_id: Some(session.tenant_id),
            tenant_slug: session.tenant_slug,
            roles: if session.roles.is_empty() {
                None
            } else {
                Some(session.roles.join(","))
            },
            name: session.display_name,
            app_id: None,
            iat: None,
            exp: None,
            jti: None,
            aud: None,
            scope: None,
        })
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(serde_json::json!({"token": jwt})).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

#[derive(Deserialize)]
pub struct SwitchTenantRequest {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
}

/// POST /auth/switch-tenant — switch to a different tenant.
pub async fn switch_tenant(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<SwitchTenantRequest>,
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

    // Verify user has access to the target tenant
    let tenant_id: uuid::Uuid = body
        .tenant_id
        .parse()
        .map_err(|_| ApiError::bad_request("BAD_REQUEST", "invalid tenantId"))?;

    let user_id: uuid::Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("invalid user_id in session"))?;
    let membership = MembershipStore::find(&state.db, user_id, tenant_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::forbidden("TENANT_ACCESS_DENIED", "Tenant access denied"))?;

    if !membership.is_active {
        return Err(ApiError::forbidden(
            "TENANT_ACCESS_DENIED",
            "Tenant access denied",
        ));
    }

    // Revoke old session, create new one with new tenant
    let _ = SessionStore::revoke(&state.db, &session_id).await;

    let tenant = TenantStore::find_by_id(&state.db, tenant_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "tenant not found"))?;

    let new_session_id = uuid::Uuid::new_v4().to_string();
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    SessionStore::create(
        &state.db,
        volta_auth_core::record::SessionRecord {
            session_id: new_session_id.clone(),
            user_id: session.user_id,
            tenant_id: body.tenant_id.clone(),
            return_to: None,
            created_at: now_epoch,
            last_active_at: now_epoch,
            expires_at: now_epoch + state.session_ttl_secs,
            invalidated_at: None,
            // #12: MFA verification does NOT carry over across tenants. If the new
            // tenant requires MFA, the user must re-verify in that tenant's context.
            // Previously we copied `session.mfa_verified_at`, which silently elevated
            // tenant B with MFA state obtained from tenant A.
            mfa_verified_at: None,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            csrf_token: None,
            email: session.email,
            tenant_slug: Some(tenant.slug),
            roles: vec![membership.role],
            display_name: session.display_name,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp =
        Json(serde_json::json!({"ok": true, "tenantId": body.tenant_id})).into_response();
    set_session_cookie(&mut resp, &new_session_id, &state);
    no_cache_headers(&mut resp);
    Ok(resp)
}
