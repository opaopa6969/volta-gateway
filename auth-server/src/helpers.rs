//! Shared helpers — cookie handling, state signing, content negotiation.

use axum::http::HeaderMap;
use axum::response::Response;
use axum_extra::extract::CookieJar;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::ApiError;
use crate::state::AppState;
use uuid::Uuid;
use volta_auth_core::policy::PolicyEngine;
use volta_auth_core::record::SessionRecord;
use volta_auth_core::store::{MembershipStore, SessionStore};

#[allow(dead_code)]
type HmacSha256 = Hmac<Sha256>;

const COOKIE_NAME: &str = "__volta_session";
/// Multi-account list cookie (Phase 2). Holds the comma-separated session ids of
/// every account signed in on this browser (Google-style multi-login). The
/// active account is still `__volta_session`; this is just the "remembered
/// accounts" hint — each id is re-validated against the SessionStore, so a stale
/// entry is harmless and simply pruned on the next `/accounts` render.
const ACCOUNTS_COOKIE: &str = "__volta_accounts";
/// Hard cap on remembered accounts to bound cookie size.
const MAX_ACCOUNTS: usize = 10;

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
        .and_then(|s| {
            s.strip_prefix("Bearer ")
                .or_else(|| s.strip_prefix("bearer "))
        })
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

// ─── テナント単位の認可 ─────────────────────────────────────────

/// テナントを対象にする管理 API の呼び出し元。
#[derive(Debug, Clone)]
pub struct TenantActor {
    pub session: SessionRecord,
    /// 対象テナントにおける呼び出し元の最上位ロール（大文字）。
    pub role: String,
    /// `Authorization: Bearer` で認可されたか（M2M client やトークン経由）。
    pub via_bearer: bool,
}

impl TenantActor {
    /// 呼び出し元が users 行を持つ利用者ならその id。M2M client は `None`。
    pub fn user_uuid(&self) -> Option<Uuid> {
        Uuid::parse_str(&self.session.user_id).ok()
    }
}

fn tenant_forbidden() -> ApiError {
    // 「そのテナントのメンバーではない」と「権限が足りない」を区別しない。
    // テナントの存在や所属の有無を漏らさないため。
    ApiError::forbidden("FORBIDDEN", "この操作を行う権限がありません")
}

/// `roles` のうち既知で最も上位のロールを返す（大小無視、未知は無視）。
fn highest_known_role(policy: &PolicyEngine, roles: &[String]) -> Option<String> {
    roles
        .iter()
        .map(|r| r.trim().to_ascii_uppercase())
        .filter(|r| policy.is_known_role(r))
        .min_by_key(|r| policy.rank(r))
}

/// テナント単位の認可判定（DB を触らない純粋関数）。
///
/// - `actor_tenant` は呼び出し元が権限を持つテナント。cookie セッションなら
///   対象テナントでの有効な membership があるときだけ `Some(target)`、
///   Bearer ならトークンの `tenant_id` クレーム。
/// - 対象テナントと一致しない、既知ロールを持たない、`min_role` 未満なら 403。
/// - `min_role` が未知なら fail-closed で 403。
///
/// 成功時は対象テナントでの最上位ロールを返す。
pub fn authorize_tenant_role(
    actor_tenant: Option<Uuid>,
    actor_roles: &[String],
    target_tenant: Uuid,
    min_role: &str,
) -> Result<String, ApiError> {
    let policy = PolicyEngine::default_policy();
    if actor_tenant != Some(target_tenant) {
        return Err(tenant_forbidden());
    }
    let min = min_role.trim().to_ascii_uppercase();
    if !policy.is_known_role(&min) {
        return Err(tenant_forbidden());
    }
    let highest = highest_known_role(&policy, actor_roles).ok_or_else(tenant_forbidden)?;
    if !policy.is_at_least(&highest, &min) {
        return Err(tenant_forbidden());
    }
    Ok(highest)
}

/// 呼び出し元が `role` を他者（招待・M2M client・ユーザー作成）に付与してよいか。
///
/// - 未知のロールは 400 `INVALID_ROLE`。
/// - OWNER は ownership transfer 以外では付与しない（403）。
/// - 呼び出し元のロールを超えるロールは付与できない（403）。
///
/// 成功時は正規化（trim + 大文字化）したロール名を返す。
pub fn authorize_role_grant(caller_role: &str, role: &str) -> Result<String, ApiError> {
    let policy = PolicyEngine::default_policy();
    let role = role.trim().to_ascii_uppercase();
    if !policy.is_known_role(&role) {
        return Err(ApiError::bad_request(
            "INVALID_ROLE",
            &format!(
                "未知のロール '{}' — {} のいずれかを指定してください",
                role,
                policy.hierarchy().join(" / ")
            ),
        ));
    }
    if role == "OWNER" {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "OWNER は付与できません（オーナー移譲を使ってください）",
        ));
    }
    let caller = caller_role.trim().to_ascii_uppercase();
    if !policy.is_known_role(&caller) || !policy.is_at_least(&caller, &role) {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "自分より上のロールは付与できません",
        ));
    }
    Ok(role)
}

/// M2M client に付ける scopes（= JWT の roles）を検証して正規化する。
///
/// カンマ／空白区切り。各要素は既知のロールで、呼び出し元のロールを超えないこと。
/// OWNER は呼び出し元が OWNER のときだけ付けられる。重複は除き、カンマ区切りで返す。
pub fn normalize_m2m_scopes(caller_role: &str, scopes: &str) -> Result<String, ApiError> {
    let policy = PolicyEngine::default_policy();
    let caller = caller_role.trim().to_ascii_uppercase();
    let mut out: Vec<String> = Vec::new();
    for raw in scopes.split(|c: char| c == ',' || c.is_whitespace()) {
        let scope = raw.trim().to_ascii_uppercase();
        if scope.is_empty() {
            continue;
        }
        if !policy.is_known_role(&scope) {
            return Err(ApiError::bad_request(
                "INVALID_SCOPE",
                &format!(
                    "未知の scope '{}' — {} のいずれかを指定してください",
                    scope,
                    policy.hierarchy().join(" / ")
                ),
            ));
        }
        if !policy.is_known_role(&caller) || !policy.is_at_least(&caller, &scope) {
            return Err(ApiError::forbidden(
                "FORBIDDEN",
                "自分より上のロールを scope に指定できません",
            ));
        }
        if !out.contains(&scope) {
            out.push(scope);
        }
    }
    Ok(out.join(","))
}

/// テナントを対象にする管理 API の共通認可。
///
/// - `Authorization: Bearer` があればそれだけで判定する（cookie には戻らない）。
///   トークンの `tenant_id` が対象テナントと一致し、roles が `min_role` 以上であること。
/// - なければ cookie セッション。対象テナントでの**有効な membership** のロールが
///   `min_role` 以上であること。membership を正とするのは、複数テナントに所属する
///   管理者がセッションを切り替えずに管理画面でテナントを選んで操作するため
///   （volta-auth-console の tenant selector）。セッション上のロールより DB の
///   membership の方が新しい。
pub async fn require_tenant_role(
    state: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    tenant_id: Uuid,
    min_role: &str,
) -> Result<TenantActor, ApiError> {
    if let Some(token) = bearer_token(headers) {
        let claims = state
            .jwt_verifier
            .verify(token)
            .map_err(|_| ApiError::unauthorized("INVALID_TOKEN", "invalid or expired token"))?;
        let roles = split_roles(claims.roles.as_deref());
        let actor_tenant = claims
            .tenant_id
            .as_deref()
            .and_then(|t| Uuid::parse_str(t.trim()).ok());
        let role = authorize_tenant_role(actor_tenant, &roles, tenant_id, min_role)?;
        return Ok(TenantActor {
            session: synthetic_session_from_claims(claims, roles),
            role,
            via_bearer: true,
        });
    }

    let session = require_session(state, jar).await?;
    let uid = Uuid::parse_str(&session.user_id).map_err(|_| tenant_forbidden())?;
    let membership = MembershipStore::find(&state.db, uid, tenant_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .filter(|m| m.is_active);
    let (actor_tenant, roles) = match membership {
        Some(m) => (Some(m.tenant_id), vec![m.role]),
        None => (None, Vec::new()),
    };
    let role = authorize_tenant_role(actor_tenant, &roles, tenant_id, min_role)?;
    Ok(TenantActor {
        session,
        role,
        via_bearer: false,
    })
}

/// 本人以外を対象にできない API（`/api/v1/users/{userId}/...`）の判定。
pub fn require_self(session: &SessionRecord, user_id: Uuid) -> Result<(), ApiError> {
    if Uuid::parse_str(session.user_id.trim()).ok() != Some(user_id) {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "他のユーザーは操作できません",
        ));
    }
    Ok(())
}

/// 発行済み M2M client の scopes を、トークンの roles に入れる前に絞り込む。
///
/// 作成時の検証（[`normalize_m2m_scopes`]）より前に作られた client が残っていても、
/// 既知のロール以外はトークンに載せない。未知の値は捨て、大文字に正規化し、
/// 重複を除いてカンマ区切りで返す（全部捨てたら空文字）。
pub fn sanitize_issued_m2m_scopes(scopes: &str) -> String {
    let policy = PolicyEngine::default_policy();
    let mut out: Vec<String> = Vec::new();
    for raw in scopes.split(|c: char| c == ',' || c.is_whitespace()) {
        let scope = raw.trim().to_ascii_uppercase();
        if scope.is_empty() || !policy.is_known_role(&scope) {
            continue;
        }
        if !out.contains(&scope) {
            out.push(scope);
        }
    }
    out.join(",")
}

// ─── システム管理者（テナント横断の管理 API） ─────────────────────

/// テナントを横断する管理 API（全テナント・全ユーザーの一覧、ユーザーの完全削除、
/// 署名鍵、全セッション等）を使えるシステム管理者の一覧。
///
/// 環境変数 `SYSTEM_ADMIN_EMAILS`（カンマ／空白区切りのメールアドレス）で明示する。
/// **未設定・空なら誰もシステム管理者ではない**（横断 API は全員 403）。
/// テナントの ADMIN / OWNER であることはシステム管理者の条件にならない。
#[derive(Debug, Clone, Default)]
pub struct SystemAdmins {
    emails: Vec<String>,
}

impl SystemAdmins {
    pub const ENV: &'static str = "SYSTEM_ADMIN_EMAILS";

    pub fn parse(raw: &str) -> Self {
        let mut emails: Vec<String> = Vec::new();
        for e in raw.split(|c: char| c == ',' || c.is_whitespace()) {
            let e = e.trim().to_ascii_lowercase();
            if e.contains('@') && !emails.contains(&e) {
                emails.push(e);
            }
        }
        Self { emails }
    }

    pub fn from_env() -> Self {
        std::env::var(Self::ENV)
            .map(|v| Self::parse(&v))
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.emails.len()
    }

    pub fn is_empty(&self) -> bool {
        self.emails.is_empty()
    }

    pub fn contains(&self, email: &str) -> bool {
        let email = email.trim().to_ascii_lowercase();
        !email.is_empty() && self.emails.contains(&email)
    }
}

fn system_admin_forbidden() -> ApiError {
    ApiError::forbidden("FORBIDDEN", "この操作はシステム管理者のみ実行できます")
}

/// システム管理者かどうかの判定（DB を触らない純粋関数）。
///
/// `user` は呼び出し元の users 行。存在し、有効で、削除されておらず、
/// メールアドレスが [`SystemAdmins`] に含まれるときだけ通す。
pub fn authorize_system_admin(
    admins: &SystemAdmins,
    user: Option<&volta_auth_core::record::UserRecord>,
) -> Result<(), ApiError> {
    let user = user.ok_or_else(system_admin_forbidden)?;
    if !user.is_active || user.deleted_at.is_some() || !admins.contains(&user.email) {
        return Err(system_admin_forbidden());
    }
    Ok(())
}

/// テナント横断の管理 API の共通認可。
///
/// - 対話ログインの cookie セッションだけを受け付ける。`Authorization: Bearer`
///   （M2M client やトークン）はテナントに閉じた権限なので、付いていれば 403。
/// - セッションの利用者の users 行を引き、[`authorize_system_admin`] で判定する。
///   メールアドレスはセッションではなく DB の値を使う。
pub async fn require_system_admin(
    state: &AppState,
    jar: &CookieJar,
    headers: Option<&HeaderMap>,
) -> Result<SessionRecord, ApiError> {
    if headers.and_then(bearer_token).is_some() {
        return Err(system_admin_forbidden());
    }
    let session = require_session(state, jar).await?;
    let uid = Uuid::parse_str(session.user_id.trim()).map_err(|_| system_admin_forbidden())?;
    let user = volta_auth_core::store::UserStore::find_by_id(&state.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    authorize_system_admin(&state.system_admins, user.as_ref())?;
    Ok(session)
}

fn split_roles(roles: Option<&str>) -> Vec<String> {
    roles
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
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
        expires_at: claims.exp.unwrap_or(now_epoch + 300),
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
    resp.headers_mut()
        .append("set-cookie", cookie.parse().unwrap());
}

/// Silent device-marker cookie for risk-based auth (Phase 4c). Long-lived,
/// opaque; its per-user hash is remembered server-side so a *missing* marker
/// flags a new device.
const DEVICE_COOKIE: &str = "__volta_kd";
const DEVICE_COOKIE_MAX_AGE: u64 = 400 * 24 * 3600; // ~400d (browser cap)

/// Existing device-marker value, if the browser presented one.
pub fn read_device_marker(jar: &CookieJar) -> Option<String> {
    jar.get(DEVICE_COOKIE)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty())
}

/// Persist/refresh the device marker on the response.
pub fn set_device_cookie(resp: &mut Response, device_id: &str, state: &AppState) {
    let mut cookie = format!(
        "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
        DEVICE_COOKIE, device_id, DEVICE_COOKIE_MAX_AGE,
    );
    if !state.cookie_domain.is_empty() {
        cookie.push_str(&format!("; Domain={}", state.cookie_domain));
    }
    if state.force_secure_cookie {
        cookie.push_str("; Secure");
    }
    resp.headers_mut()
        .append("set-cookie", cookie.parse().unwrap());
}

/// Read the remembered-accounts list (session ids) from the request cookie.
/// Order is preserved; entries are opaque and validated by the caller.
pub fn read_accounts(jar: &CookieJar) -> Vec<String> {
    jar.get(ACCOUNTS_COOKIE)
        .map(|c| {
            c.value()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Dedup (first-wins), drop empties, cap to `MAX_ACCOUNTS`. Pure — the value
/// that goes into the accounts cookie.
pub fn dedup_cap_accounts(ids: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    ids.iter()
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert((*id).clone()))
        .take(MAX_ACCOUNTS)
        .cloned()
        .collect()
}

/// Set the remembered-accounts cookie (deduped, capped, same attrs as the
/// session cookie). An empty list clears it.
pub fn set_accounts_cookie(resp: &mut Response, ids: &[String], state: &AppState) {
    let deduped = dedup_cap_accounts(ids);
    let mut cookie = if deduped.is_empty() {
        format!(
            "{}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
            ACCOUNTS_COOKIE
        )
    } else {
        format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
            ACCOUNTS_COOKIE,
            deduped.join(","),
            state.session_ttl_secs,
        )
    };
    if !state.cookie_domain.is_empty() {
        cookie.push_str(&format!("; Domain={}", state.cookie_domain));
    }
    if state.force_secure_cookie {
        cookie.push_str("; Secure");
    }
    resp.headers_mut()
        .append("set-cookie", cookie.parse().unwrap());
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
    resp.headers_mut()
        .append("set-cookie", cookie.parse().unwrap());
}

/// Check if Accept header wants JSON.
pub fn is_json_accept(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false)
}

/// Sign OIDC state parameter with HMAC-SHA256.
/// Format: `{flow_id}:{return_to}:{invite}:{hmac_hex}`
#[allow(dead_code)]
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
#[allow(dead_code)]
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
            let invite_str = &rest[pos + 1..];
            let invite = if invite_str.is_empty() {
                None
            } else {
                Some(invite_str.to_string())
            };
            Some((flow_id, return_to, invite))
        }
        None => {
            // No invite
            Some((flow_id, rest.to_string(), None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn dedup_cap_accounts_keeps_first_and_caps() {
        // first-wins dedup, empties dropped
        let ids = vec!["a".into(), "b".into(), "a".into(), "".into(), "c".into()];
        assert_eq!(dedup_cap_accounts(&ids), vec!["a", "b", "c"]);
        // capped at MAX_ACCOUNTS
        let many: Vec<String> = (0..(MAX_ACCOUNTS + 5)).map(|i| format!("s{i}")).collect();
        assert_eq!(dedup_cap_accounts(&many).len(), MAX_ACCOUNTS);
    }

    #[test]
    fn read_accounts_splits_and_filters() {
        use axum::http::header::COOKIE;
        use axum_extra::extract::CookieJar;
        let mut h = HeaderMap::new();
        h.insert(COOKIE, "__volta_accounts=s1,s2,,s3".parse().unwrap());
        let jar = CookieJar::from_headers(&h);
        assert_eq!(read_accounts(&jar), vec!["s1", "s2", "s3"]);
        // absent cookie → empty
        assert!(read_accounts(&CookieJar::from_headers(&HeaderMap::new())).is_empty());
    }

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

    // ── テナント単位の認可 ─────────────────────────────────────

    fn tid(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn roles(rs: &[&str]) -> Vec<String> {
        rs.iter().map(|r| r.to_string()).collect()
    }

    #[test]
    fn tenant_role_other_tenant_is_forbidden() {
        // 自テナントの ADMIN/OWNER でも、別テナントを指定したら 403
        for r in ["ADMIN", "OWNER"] {
            let err =
                authorize_tenant_role(Some(tid(1)), &roles(&[r]), tid(2), "ADMIN").unwrap_err();
            assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        }
        // 所属なし（cookie で membership が無い / Bearer に tenant_id が無い）
        let err = authorize_tenant_role(None, &roles(&["OWNER"]), tid(2), "ADMIN").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn tenant_role_own_tenant_admin_and_owner_succeed() {
        assert_eq!(
            authorize_tenant_role(Some(tid(1)), &roles(&["ADMIN"]), tid(1), "ADMIN").unwrap(),
            "ADMIN"
        );
        assert_eq!(
            authorize_tenant_role(Some(tid(1)), &roles(&["owner"]), tid(1), "ADMIN").unwrap(),
            "OWNER"
        );
        // 複数ロールなら最上位を返す（M2M の scopes は複数になり得る）
        assert_eq!(
            authorize_tenant_role(
                Some(tid(1)),
                &roles(&["VIEWER", " admin ", "typo"]),
                tid(1),
                "ADMIN"
            )
            .unwrap(),
            "ADMIN"
        );
    }

    #[test]
    fn tenant_role_below_min_is_forbidden() {
        for r in ["MEMBER", "OPERATOR", "VIEWER"] {
            let err =
                authorize_tenant_role(Some(tid(1)), &roles(&[r]), tid(1), "ADMIN").unwrap_err();
            assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN, "{r}");
        }
        // 未知ロールだけ・ロール無しは何も持たない扱い
        assert!(
            authorize_tenant_role(Some(tid(1)), &roles(&["SUPERUSER"]), tid(1), "VIEWER").is_err()
        );
        assert!(authorize_tenant_role(Some(tid(1)), &[], tid(1), "VIEWER").is_err());
        // MEMBER 以上で足りる参照系は MEMBER で通る
        assert!(authorize_tenant_role(Some(tid(1)), &roles(&["MEMBER"]), tid(1), "MEMBER").is_ok());
    }

    #[test]
    fn tenant_role_unknown_min_role_fails_closed() {
        assert!(authorize_tenant_role(Some(tid(1)), &roles(&["OWNER"]), tid(1), "ADMNI").is_err());
    }

    #[test]
    fn role_grant_rejects_owner_and_unknown() {
        let err = authorize_role_grant("OWNER", "OWNER").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        let err = authorize_role_grant("OWNER", "owner").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        let err = authorize_role_grant("OWNER", "SUPERUSER").unwrap_err();
        assert_eq!(err.code, "INVALID_ROLE");
        assert!(authorize_role_grant("OWNER", "").is_err());
    }

    #[test]
    fn role_grant_cannot_exceed_caller() {
        // ADMIN は OWNER 相当を付与できない（OWNER 拒否）、OPERATOR は ADMIN を付与できない
        assert!(authorize_role_grant("ADMIN", "OWNER").is_err());
        let err = authorize_role_grant("OPERATOR", "ADMIN").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        let err = authorize_role_grant("MEMBER", "OPERATOR").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }

    #[test]
    fn role_grant_allows_own_role_or_lower() {
        assert_eq!(authorize_role_grant("ADMIN", "admin").unwrap(), "ADMIN");
        assert_eq!(authorize_role_grant("ADMIN", " member ").unwrap(), "MEMBER");
        assert_eq!(authorize_role_grant("OWNER", "ADMIN").unwrap(), "ADMIN");
        assert_eq!(authorize_role_grant("ADMIN", "VIEWER").unwrap(), "VIEWER");
    }

    #[test]
    fn m2m_scopes_are_validated_against_caller() {
        // ADMIN は ADMIN 以下の scope を付けられる。正規化・重複除去される。
        assert_eq!(
            normalize_m2m_scopes("ADMIN", "admin, member ADMIN").unwrap(),
            "ADMIN,MEMBER"
        );
        assert_eq!(normalize_m2m_scopes("ADMIN", "").unwrap(), "");
        // 呼び出し元を超える scope は 403
        let err = normalize_m2m_scopes("ADMIN", "OWNER").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        // 未知の scope は 400
        let err = normalize_m2m_scopes("OWNER", "ADMIN,root").unwrap_err();
        assert_eq!(err.code, "INVALID_SCOPE");
        // OWNER の呼び出し元なら OWNER scope も可（自分のロールを超えない）
        assert_eq!(normalize_m2m_scopes("OWNER", "OWNER").unwrap(), "OWNER");
    }

    fn session_for(user_id: &str) -> SessionRecord {
        SessionRecord {
            session_id: "s".into(),
            user_id: user_id.into(),
            tenant_id: String::new(),
            return_to: None,
            created_at: 0,
            last_active_at: 0,
            expires_at: 0,
            invalidated_at: None,
            mfa_verified_at: None,
            ip_address: None,
            user_agent: None,
            csrf_token: None,
            email: None,
            tenant_slug: None,
            roles: vec![],
            display_name: None,
        }
    }

    #[test]
    fn require_self_only_matches_own_user_id() {
        let me = Uuid::from_u128(7);
        let s = session_for(&me.to_string());
        assert!(require_self(&s, me).is_ok());
        let err = require_self(&s, Uuid::from_u128(8)).unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        // 大文字表記でも同じ UUID なら本人
        let s = session_for(&me.to_string().to_ascii_uppercase());
        assert!(require_self(&s, me).is_ok());
        // M2M（UUID でない subject）は本人扱いしない
        assert!(require_self(&session_for("m2m_abcd1234"), me).is_err());
    }

    #[test]
    fn issued_m2m_scopes_drop_unknown_values() {
        // 作成時の検証より前に保存された値が残っていても、既知のロールだけに絞る。
        assert_eq!(
            sanitize_issued_m2m_scopes("admin, superuser,MEMBER admin"),
            "ADMIN,MEMBER"
        );
        assert_eq!(sanitize_issued_m2m_scopes("root,*,system"), "");
        assert_eq!(sanitize_issued_m2m_scopes(""), "");
        assert_eq!(sanitize_issued_m2m_scopes("OWNER"), "OWNER");
    }

    fn user_with(email: &str, active: bool, deleted: bool) -> volta_auth_core::record::UserRecord {
        volta_auth_core::record::UserRecord {
            id: Uuid::from_u128(1),
            email: email.into(),
            display_name: None,
            google_sub: None,
            created_at: chrono::Utc::now(),
            is_active: active,
            locale: None,
            deleted_at: deleted.then(chrono::Utc::now),
        }
    }

    #[test]
    fn system_admins_parse_and_match_case_insensitively() {
        let admins =
            SystemAdmins::parse(" Root@Example.com, ops@example.com  root@example.com,,x ");
        assert_eq!(admins.len(), 2);
        assert!(admins.contains("root@example.com"));
        assert!(admins.contains(" OPS@example.COM "));
        assert!(!admins.contains("other@example.com"));
        assert!(!admins.contains(""));
        assert!(SystemAdmins::parse("").is_empty());
    }

    #[test]
    fn system_admin_requires_explicit_listing() {
        let admins = SystemAdmins::parse("root@example.com");
        assert!(
            authorize_system_admin(&admins, Some(&user_with("ROOT@example.com", true, false)))
                .is_ok()
        );
        // 一覧にない・無効・削除済み・users 行なしは 403
        for user in [
            Some(user_with("admin@example.com", true, false)),
            Some(user_with("root@example.com", false, false)),
            Some(user_with("root@example.com", true, true)),
            None,
        ] {
            let err = authorize_system_admin(&admins, user.as_ref()).unwrap_err();
            assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
        }
        // 未設定なら誰も通らない（安全側）
        let none = SystemAdmins::default();
        assert!(
            authorize_system_admin(&none, Some(&user_with("root@example.com", true, false)))
                .is_err()
        );
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
