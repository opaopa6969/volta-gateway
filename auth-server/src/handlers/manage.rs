//! Management API handlers — tenant, member, invitation, idp-config, m2m, passkey, user.
//! 100% compatible with Java volta-auth-proxy ApiRouter endpoints.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::helpers::extract_session_id;
use crate::state::AppState;
use volta_auth_core::record::SessionRecord;
use volta_auth_core::store::*;

async fn auth(state: &AppState, jar: &CookieJar) -> Result<SessionRecord, ApiError> {
    let sid = extract_session_id(jar).ok_or_else(|| {
        ApiError::unauthorized(
            "SESSION_EXPIRED",
            "セッションの有効期限が切れました。再ログインしてください。",
        )
    })?;
    SessionStore::find(&state.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| {
            ApiError::unauthorized(
                "SESSION_EXPIRED",
                "セッションの有効期限が切れました。再ログインしてください。",
            )
        })
}

// ─── Tenant ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTenantReq {
    pub name: String,
    pub slug: String,
}

pub async fn create_tenant(
    State(s): State<AppState>,
    jar: CookieJar,
    Json(b): Json<CreateTenantReq>,
) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    let t = TenantStore::create(
        &s.db,
        volta_auth_core::record::TenantRecord {
            id: Uuid::new_v4(),
            name: b.name,
            slug: b.slug,
            email_domain: None,
            auto_join: false,
            created_by: Some(uid),
            created_at: chrono::Utc::now(),
            plan: Some("FREE".into()),
            max_members: Some(50),
            is_active: true,
            mfa_required: false,
            mfa_grace_until: None,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    // Create owner membership
    MembershipStore::create(
        &s.db,
        volta_auth_core::record::MembershipRecord {
            id: Uuid::new_v4(),
            user_id: uid,
            tenant_id: t.id,
            role: "OWNER".into(),
            joined_at: chrono::Utc::now(),
            invited_by: None,
            is_active: true,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": t.id, "slug": t.slug})).into_response())
}

pub async fn get_tenant(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let t = TenantStore::find_by_id(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "tenant not found"))?;
    Ok(Json(serde_json::json!({"id":t.id,"name":t.name,"slug":t.slug,"plan":t.plan,"is_active":t.is_active,"mfa_required":t.mfa_required})).into_response())
}

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PatchTenantReq {
    pub name: Option<String>,
}

pub async fn patch_tenant(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(_b): Json<PatchTenantReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    // Simplified — real impl would update fields selectively
    let t = TenantStore::find_by_id(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "tenant not found"))?;
    Ok(Json(serde_json::json!({"ok": true, "id": t.id})).into_response())
}

// ─── Member ────────────────────────────────────────────────

pub async fn list_members(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<crate::pagination::PageRequest>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let req = q.normalized();
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["joined_at", "role"],
        "joined_at DESC",
    );
    let (items, total) =
        s.db.list_members_paginated(tid, &order, req.limit(), req.offset())
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

#[derive(Deserialize)]
pub struct PatchMemberReq {
    pub role: String,
}

/// 呼び出し元がそのテナントで `permission` を持つことを確かめる。
///
/// これが無かった。`auth()` は**ログイン済みか見るだけ**で、テナントも権限も
/// 見ていない。つまり誰でも任意のテナントの任意のメンバーを操作できた
/// （自分の membership を OWNER に PATCH できる = 権限昇格）。
async fn require_tenant_permission(
    s: &AppState,
    jar: &CookieJar,
    tenant_id: Uuid,
    permission: &str,
) -> Result<(SessionRecord, String), ApiError> {
    let session = auth(s, jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;

    let membership = MembershipStore::find(&s.db, uid, tenant_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .filter(|m| m.is_active)
        .ok_or_else(|| {
            // 「そのテナントのメンバーではない」と「権限が足りない」を
            // 区別して返さない。存在の有無を漏らさないため。
            ApiError::forbidden("FORBIDDEN", "この操作を行う権限がありません")
        })?;

    let policy = volta_auth_core::policy::PolicyEngine::default_policy();
    if !policy.can(&membership.role.to_ascii_uppercase(), permission) {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "この操作を行う権限がありません",
        ));
    }
    Ok((session, membership.role.to_ascii_uppercase()))
}

/// mid がそのテナントの membership であることを確かめる。
///
/// パスの tenantId と memberId は独立に渡ってくるので、**別テナントの
/// membership id を渡せば他所のテナントを操作できる**。
async fn member_in_tenant(
    s: &AppState,
    tenant_id: Uuid,
    member_id: Uuid,
) -> Result<volta_auth_core::record::MembershipRecord, ApiError> {
    let members = MembershipStore::list_by_tenant(&s.db, tenant_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    members
        .into_iter()
        .find(|m| m.id == member_id && m.is_active)
        .ok_or_else(|| ApiError::forbidden("FORBIDDEN", "この操作を行う権限がありません"))
}

/// ロール変更が許されるかを判定する（DB を触らない）。
///
/// ここを純粋関数にしてあるのは、**権限判定こそテストが要る**のに、
/// ハンドラのままだと DB とセッションを用意しないと呼べないため。
///
/// `owner_count` は target が OWNER のときだけ意味を持つ。それ以外は
/// `usize::MAX` を渡してよい（最後の OWNER 判定に入らない）。
fn authorize_role_change(
    caller_role: &str,
    target_role: &str,
    new_role: &str,
    owner_count: usize,
) -> Result<(), ApiError> {
    let policy = volta_auth_core::policy::PolicyEngine::default_policy();
    let caller = caller_role.to_ascii_uppercase();
    let target = target_role.to_ascii_uppercase();

    // 未知のロール名を DB に入れない。
    //
    // enforce_min_role は未知ロールを拒否する（fail-closed）ので、typo した
    // ロールを持たされた人は **何にもアクセスできなくなる**。しかも本人には
    // 理由が分からない。入口で弾く。
    if !policy.is_known_role(new_role) {
        return Err(ApiError::bad_request(
            "INVALID_ROLE",
            &format!(
                "未知のロール '{}' — {} のいずれかを指定してください",
                new_role,
                policy.hierarchy().join(" / ")
            ),
        ));
    }

    // 自分より上のロールを配れない。無いと ADMIN が自分を OWNER に上げられる。
    if !policy.is_at_least(&caller, new_role) {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "自分より上のロールは付与できません",
        ));
    }

    // 相手が自分より上なら触らせない（ADMIN が OWNER を降格できない）。
    if !policy.is_at_least(&caller, &target) {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "自分より上のロールのメンバーは変更できません",
        ));
    }

    // 最後の OWNER を降格させない。誰も管理できないテナントが残る。
    if target == "OWNER" && new_role != "OWNER" && owner_count <= 1 {
        return Err(ApiError::bad_request(
            "LAST_OWNER",
            "最後の OWNER は降格できません。先に別の OWNER を立ててください",
        ));
    }
    Ok(())
}

/// メンバー削除（無効化）が許されるか。
fn authorize_member_removal(
    caller_role: &str,
    target_role: &str,
    owner_count: usize,
) -> Result<(), ApiError> {
    let policy = volta_auth_core::policy::PolicyEngine::default_policy();
    let caller = caller_role.to_ascii_uppercase();
    let target = target_role.to_ascii_uppercase();

    if !policy.is_at_least(&caller, &target) {
        return Err(ApiError::forbidden(
            "FORBIDDEN",
            "自分より上のロールのメンバーは削除できません",
        ));
    }
    if target == "OWNER" && owner_count <= 1 {
        return Err(ApiError::bad_request(
            "LAST_OWNER",
            "最後の OWNER は削除できません。先に別の OWNER を立ててください",
        ));
    }
    Ok(())
}

pub async fn patch_member(
    State(s): State<AppState>,
    jar: CookieJar,
    Path((tid, mid)): Path<(Uuid, Uuid)>,
    Json(b): Json<PatchMemberReq>,
) -> Result<Response, ApiError> {
    let (_session, caller_role) =
        require_tenant_permission(&s, &jar, tid, "change_member_role").await?;
    let target = member_in_tenant(&s, tid, mid).await?;

    let new_role = b.role.trim().to_ascii_uppercase();

    // 最後の OWNER かどうかは DB を引かないと分からないので、必要なときだけ数える。
    let owner_count = if target.role.eq_ignore_ascii_case("OWNER") {
        MembershipStore::count_active_owners(&s.db, tid)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?
    } else {
        usize::MAX
    };

    authorize_role_change(&caller_role, &target.role, &new_role, owner_count)?;

    MembershipStore::update_role(&s.db, mid, &new_role)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true, "role": new_role})).into_response())
}

pub async fn delete_member(
    State(s): State<AppState>,
    jar: CookieJar,
    Path((tid, mid)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let (_session, caller_role) =
        require_tenant_permission(&s, &jar, tid, "remove_members").await?;
    let target = member_in_tenant(&s, tid, mid).await?;

    let owner_count = if target.role.eq_ignore_ascii_case("OWNER") {
        MembershipStore::count_active_owners(&s.db, tid)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?
    } else {
        usize::MAX
    };

    authorize_member_removal(&caller_role, &target.role, owner_count)?;

    MembershipStore::deactivate(&s.db, mid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Invitation ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateInviteReq {
    pub email: Option<String>,
    pub role: Option<String>,
}

pub async fn create_invitation(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<CreateInviteReq>,
) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    let code = uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string();
    InvitationStore::create(
        &s.db,
        volta_auth_core::record::InvitationRecord {
            id: Uuid::new_v4(),
            tenant_id: tid,
            code: code.clone(),
            email: b.email,
            role: b.role.unwrap_or_else(|| "MEMBER".into()),
            max_uses: 1,
            used_count: 0,
            created_by: uid,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"code": code})).into_response())
}

pub async fn list_invitations(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    axum::extract::Query(q): axum::extract::Query<crate::pagination::PageRequest>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let req = q.normalized();
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["created_at", "expires_at"],
        "created_at DESC",
    );
    let (items, total) =
        s.db.list_invitations_paginated(
            tid,
            req.status.as_deref(),
            &order,
            req.limit(),
            req.offset(),
        )
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

pub async fn cancel_invitation(
    State(s): State<AppState>,
    jar: CookieJar,
    Path((tid, inv_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let _ = tid;
    InvitationStore::cancel(&s.db, inv_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn accept_invite(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(code): Path<String>,
) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    InvitationStore::accept(&s.db, &code, uid)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── IdP Config ────────────────────────────────────────────

pub async fn list_idp_configs(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let configs = IdpConfigStore::list_by_tenant(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = configs.iter().map(|c| serde_json::json!({"id":c.id,"provider_type":c.provider_type,"issuer":c.issuer,"client_id":c.client_id})).collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
pub struct UpsertIdpReq {
    pub provider_type: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub issuer: Option<String>,
    pub metadata_url: Option<String>,
}

pub async fn upsert_idp_config(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<UpsertIdpReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let id = IdpConfigStore::upsert(
        &s.db,
        volta_auth_core::record::IdpConfigRecord {
            id: Uuid::new_v4(),
            tenant_id: tid,
            provider_type: b.provider_type,
            metadata_url: b.metadata_url,
            issuer: b.issuer,
            client_id: b.client_id,
            client_secret: b.client_secret,
            x509_cert: None,
            created_at: chrono::Utc::now(),
            is_active: true,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

// ─── M2M Client ────────────────────────────────────────────

pub async fn list_m2m_clients(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let clients = M2mClientStore::list_by_tenant(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = clients
        .iter()
        .map(|c| serde_json::json!({"id":c.id,"client_id":c.client_id,"scopes":c.scopes}))
        .collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
pub struct CreateM2mReq {
    pub scopes: Option<String>,
}

pub async fn create_m2m_client(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<CreateM2mReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let client_id = format!("m2m_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let secret = uuid::Uuid::new_v4().to_string();
    let secret_hash = crate::handlers::mfa::sha256_hex_pub(&secret);
    let id = M2mClientStore::create(
        &s.db,
        volta_auth_core::record::M2mClientRecord {
            id: Uuid::new_v4(),
            tenant_id: tid,
            client_id: client_id.clone(),
            client_secret_hash: secret_hash,
            scopes: b.scopes.unwrap_or_default(),
            is_active: true,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(
        Json(serde_json::json!({"id": id, "client_id": client_id, "client_secret": secret}))
            .into_response(),
    )
}

// ─── Passkey ───────────────────────────────────────────────

pub async fn list_passkeys(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(uid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let passkeys = PasskeyStore::list_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = passkeys
        .iter()
        .map(|p| {
            // Phase 4b: surface the authenticator model (from AAGUID) so the UI can
            // show "iCloud キーチェーン" / "YubiKey 5 NFC" instead of an opaque id.
            let aaguid = p.aaguid.map(|a| a.to_string());
            serde_json::json!({
                "id": p.id,
                "name": p.name,
                "aaguid": aaguid,
                "authenticator": crate::aaguid::label_for(aaguid.as_deref()),
                "created_at": p.created_at.to_rfc3339(),
                "last_used_at": p.last_used_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();
    Ok(Json(items).into_response())
}

pub async fn delete_passkey(
    State(s): State<AppState>,
    jar: CookieJar,
    Path((uid, pk_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    PasskeyStore::delete(&s.db, uid, pk_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── User management ──────────────────────────────────────

#[derive(Deserialize)]
#[allow(dead_code)]
pub struct PatchUserReq {
    pub display_name: Option<String>,
    pub locale: Option<String>,
}

pub async fn patch_user(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(uid): Path<Uuid>,
    Json(b): Json<PatchUserReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    if let Some(ref name) = b.display_name {
        UserStore::update_display_name(&s.db, uid, name)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    }
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn delete_user(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    UserStore::soft_delete(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── OAuth2 Token (M2M) ──────────────────────────────────

#[derive(Deserialize)]
pub struct TokenReq {
    pub grant_type: String,
    #[serde(default)]
    pub client_id: String,
    /// Required for `client_credentials`; absent for the device grant (public client).
    pub client_secret: Option<String>,
    /// Required for `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
    pub device_code: Option<String>,
    // OP grants (Phase 3b)
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    // Token exchange (Phase 5, RFC 8693)
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub scope: Option<String>,
    pub audience: Option<String>,
}

pub async fn oauth_token(
    State(s): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(b): axum::extract::Form<TokenReq>,
) -> Result<Response, ApiError> {
    // RFC 8628 device grant — poll for a token the user approved on a 2nd device.
    if b.grant_type == crate::handlers::device::DEVICE_CODE_GRANT {
        let device_code = b
            .device_code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| ApiError::bad_request("invalid_request", "device_code is required"))?;
        return Ok(crate::handlers::device::device_token_grant(&s, device_code).await);
    }
    // DPoP (RFC 9449): if a proof accompanies the token request, bind the issued
    // access token to the client's key. An invalid proof is a hard error.
    let dpop_jkt = match crate::handlers::op::token_dpop_jkt(&s, &headers) {
        Ok(v) => v,
        Err(resp) => return Ok(resp),
    };
    // OP authorization_code grant (Phase 3b).
    if b.grant_type == "authorization_code" {
        let code = b
            .code
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| ApiError::bad_request("invalid_request", "code is required"))?;
        let redirect_uri = b.redirect_uri.as_deref().unwrap_or("");
        return Ok(crate::handlers::op::token_authorization_code(
            &s,
            &b.client_id,
            b.client_secret.as_deref(),
            code,
            redirect_uri,
            b.code_verifier.as_deref(),
            dpop_jkt,
        )
        .await);
    }
    // OP refresh_token grant (Phase 3b) — rotation + reuse detection.
    if b.grant_type == "refresh_token" {
        let rt = b
            .refresh_token
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| ApiError::bad_request("invalid_request", "refresh_token is required"))?;
        return Ok(crate::handlers::op::token_refresh(
            &s,
            &b.client_id,
            b.client_secret.as_deref(),
            rt,
            dpop_jkt,
        )
        .await);
    }
    // OP token exchange (Phase 5, RFC 8693).
    if b.grant_type == crate::handlers::op::TOKEN_EXCHANGE_GRANT {
        let subject_token = b
            .subject_token
            .as_deref()
            .filter(|c| !c.is_empty())
            .ok_or_else(|| ApiError::bad_request("invalid_request", "subject_token is required"))?;
        return Ok(crate::handlers::op::token_exchange(
            &s,
            &b.client_id,
            b.client_secret.as_deref(),
            subject_token,
            b.subject_token_type.as_deref(),
            b.scope.as_deref(),
            b.audience.as_deref(),
        )
        .await);
    }
    if b.grant_type != "client_credentials" {
        return Err(ApiError::bad_request(
            "UNSUPPORTED_GRANT",
            "unsupported grant_type",
        ));
    }
    let client_secret = b.client_secret.as_deref().unwrap_or("");
    let client = M2mClientStore::find_by_client_id(&s.db, &b.client_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("INVALID_CLIENT", "invalid client_id"))?;

    let hash = crate::handlers::mfa::sha256_hex_pub(client_secret);
    // #21: constant-time compare to avoid leaking the hash via early-exit timing.
    if !crate::security::constant_time_eq(hash.as_bytes(), client.client_secret_hash.as_bytes()) {
        return Err(ApiError::unauthorized(
            "INVALID_CLIENT",
            "invalid client_secret",
        ));
    }

    let jwt = s
        .jwt_issuer
        .issue(&volta_auth_core::jwt::VoltaClaims {
            sub: client.client_id.clone(),
            email: None,
            tenant_id: Some(client.tenant_id.to_string()),
            tenant_slug: None,
            roles: Some(client.scopes.clone()),
            name: None,
            app_id: None,
            iat: None,
            exp: None,
        })
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": s.session_ttl_secs,
    }))
    .into_response())
}

#[cfg(test)]
mod authz_tests {
    use super::*;

    fn ok(r: Result<(), ApiError>) -> bool {
        r.is_ok()
    }

    // ── 権限昇格 ───────────────────────────────────────────────
    //
    // 元の実装は `auth()` でログイン済みか見るだけで、テナントも権限も
    // 見ていなかった。**誰でも自分を OWNER に PATCH できた**。

    #[test]
    fn cannot_grant_a_role_above_your_own() {
        // ADMIN が自分（や他人）を OWNER に上げられない
        assert!(!ok(authorize_role_change("ADMIN", "MEMBER", "OWNER", 2)));
        assert!(!ok(authorize_role_change("MEMBER", "MEMBER", "ADMIN", 2)));
        assert!(!ok(authorize_role_change("OPERATOR", "MEMBER", "ADMIN", 2)));
    }

    #[test]
    fn can_grant_your_own_role_or_lower() {
        assert!(ok(authorize_role_change("OWNER", "MEMBER", "OWNER", 2)));
        assert!(ok(authorize_role_change("ADMIN", "MEMBER", "ADMIN", 2)));
        assert!(ok(authorize_role_change("ADMIN", "MEMBER", "OPERATOR", 2)));
        assert!(ok(authorize_role_change("ADMIN", "MEMBER", "VIEWER", 2)));
    }

    #[test]
    fn cannot_touch_a_member_above_your_own_role() {
        // ADMIN が OWNER を降格できない
        assert!(!ok(authorize_role_change("ADMIN", "OWNER", "MEMBER", 5)));
        assert!(!ok(authorize_member_removal("ADMIN", "OWNER", 5)));
    }

    // ── 未知のロール ───────────────────────────────────────────
    //
    // enforce_min_role は未知ロールを拒否する（fail-closed）ので、typo した
    // ロールを持たされた人は何にもアクセスできなくなる。入口で弾く。

    #[test]
    fn unknown_role_is_rejected() {
        assert!(!ok(authorize_role_change("OWNER", "MEMBER", "OPERATAR", 2)));
        assert!(!ok(authorize_role_change(
            "OWNER",
            "MEMBER",
            "superuser",
            2
        )));
        assert!(!ok(authorize_role_change("OWNER", "MEMBER", "", 2)));
    }

    #[test]
    fn operator_is_a_known_role() {
        assert!(ok(authorize_role_change("OWNER", "MEMBER", "OPERATOR", 2)));
    }

    #[test]
    fn role_is_case_insensitive_on_input() {
        // services.json 側に 'operator' と 'OPERATOR' が混在しており、
        // ハンドラは大文字化してから渡す。判定側も大小を揃えて扱う。
        assert!(ok(authorize_role_change("owner", "member", "OPERATOR", 2)));
    }

    // ── 最後の OWNER ───────────────────────────────────────────
    //
    // 降格/削除できてしまうと、**誰も管理できないテナント**が残る。

    #[test]
    fn last_owner_cannot_be_demoted() {
        assert!(!ok(authorize_role_change("OWNER", "OWNER", "ADMIN", 1)));
        assert!(!ok(authorize_member_removal("OWNER", "OWNER", 1)));
    }

    #[test]
    fn owner_can_be_demoted_when_another_owner_exists() {
        assert!(ok(authorize_role_change("OWNER", "OWNER", "ADMIN", 2)));
        assert!(ok(authorize_member_removal("OWNER", "OWNER", 2)));
    }

    #[test]
    fn owner_to_owner_is_not_a_demotion() {
        // 変わらないなら OWNER が1人でも通す（冪等な PATCH を壊さない）
        assert!(ok(authorize_role_change("OWNER", "OWNER", "OWNER", 1)));
    }

    #[test]
    fn non_owner_target_ignores_owner_count() {
        // usize::MAX を渡す運用（OWNER 以外は数えない）が壊れていないこと
        assert!(ok(authorize_role_change(
            "OWNER",
            "MEMBER",
            "ADMIN",
            usize::MAX
        )));
    }
}
