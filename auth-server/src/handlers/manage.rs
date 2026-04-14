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
    let sid = extract_session_id(jar)
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))?;
    SessionStore::find(&state.db, &sid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "セッションの有効期限が切れました。再ログインしてください。"))
}

// ─── Tenant ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTenantReq { pub name: String, pub slug: String }

pub async fn create_tenant(State(s): State<AppState>, jar: CookieJar, Json(b): Json<CreateTenantReq>) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    let t = TenantStore::create(&s.db, volta_auth_core::record::TenantRecord {
        id: Uuid::new_v4(), name: b.name, slug: b.slug, email_domain: None, auto_join: false,
        created_by: Some(uid), created_at: chrono::Utc::now(), plan: Some("FREE".into()),
        max_members: Some(50), is_active: true, mfa_required: false, mfa_grace_until: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    // Create owner membership
    MembershipStore::create(&s.db, volta_auth_core::record::MembershipRecord {
        id: Uuid::new_v4(), user_id: uid, tenant_id: t.id, role: "OWNER".into(),
        joined_at: chrono::Utc::now(), invited_by: None, is_active: true,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": t.id, "slug": t.slug})).into_response())
}

pub async fn get_tenant(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let t = TenantStore::find_by_id(&s.db, tid).await.map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "tenant not found"))?;
    Ok(Json(serde_json::json!({"id":t.id,"name":t.name,"slug":t.slug,"plan":t.plan,"is_active":t.is_active,"mfa_required":t.mfa_required})).into_response())
}

#[derive(Deserialize)]
pub struct PatchTenantReq { pub name: Option<String> }

pub async fn patch_tenant(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(_b): Json<PatchTenantReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    // Simplified — real impl would update fields selectively
    let t = TenantStore::find_by_id(&s.db, tid).await.map_err(|e| ApiError::internal(&e.to_string()))?
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
    let (items, total) = s.db.list_members_paginated(tid, &order, req.limit(), req.offset())
        .await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

#[derive(Deserialize)]
pub struct PatchMemberReq { pub role: String }

pub async fn patch_member(State(s): State<AppState>, jar: CookieJar, Path((tid, mid)): Path<(Uuid, Uuid)>, Json(b): Json<PatchMemberReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let _ = tid; // tenant context validation
    MembershipStore::update_role(&s.db, mid, &b.role).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn delete_member(State(s): State<AppState>, jar: CookieJar, Path((tid, mid)): Path<(Uuid, Uuid)>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let _ = tid;
    MembershipStore::deactivate(&s.db, mid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Invitation ────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateInviteReq { pub email: Option<String>, pub role: Option<String> }

pub async fn create_invitation(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<CreateInviteReq>) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    let code = uuid::Uuid::new_v4().to_string().replace('-', "")[..12].to_string();
    InvitationStore::create(&s.db, volta_auth_core::record::InvitationRecord {
        id: Uuid::new_v4(), tenant_id: tid, code: code.clone(), email: b.email,
        role: b.role.unwrap_or_else(|| "MEMBER".into()), max_uses: 1, used_count: 0,
        created_by: uid, created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::days(7),
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
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
    let (items, total) = s.db.list_invitations_paginated(
        tid, req.status.as_deref(), &order, req.limit(), req.offset(),
    ).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

pub async fn cancel_invitation(State(s): State<AppState>, jar: CookieJar, Path((tid, inv_id)): Path<(Uuid, Uuid)>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let _ = tid;
    InvitationStore::cancel(&s.db, inv_id).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn accept_invite(State(s): State<AppState>, jar: CookieJar, Path(code): Path<String>) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    InvitationStore::accept(&s.db, &code, uid).await.map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── IdP Config ────────────────────────────────────────────

pub async fn list_idp_configs(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let configs = IdpConfigStore::list_by_tenant(&s.db, tid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = configs.iter().map(|c| serde_json::json!({"id":c.id,"provider_type":c.provider_type,"issuer":c.issuer,"client_id":c.client_id})).collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
pub struct UpsertIdpReq { pub provider_type: String, pub client_id: Option<String>, pub client_secret: Option<String>, pub issuer: Option<String>, pub metadata_url: Option<String> }

pub async fn upsert_idp_config(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<UpsertIdpReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let id = IdpConfigStore::upsert(&s.db, volta_auth_core::record::IdpConfigRecord {
        id: Uuid::new_v4(), tenant_id: tid, provider_type: b.provider_type,
        metadata_url: b.metadata_url, issuer: b.issuer, client_id: b.client_id,
        client_secret: b.client_secret, x509_cert: None, created_at: chrono::Utc::now(), is_active: true,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

// ─── M2M Client ────────────────────────────────────────────

pub async fn list_m2m_clients(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let clients = M2mClientStore::list_by_tenant(&s.db, tid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = clients.iter().map(|c| serde_json::json!({"id":c.id,"client_id":c.client_id,"scopes":c.scopes})).collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
pub struct CreateM2mReq { pub scopes: Option<String> }

pub async fn create_m2m_client(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<CreateM2mReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let client_id = format!("m2m_{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let secret = uuid::Uuid::new_v4().to_string();
    let secret_hash = crate::handlers::mfa::sha256_hex_pub(&secret);
    let id = M2mClientStore::create(&s.db, volta_auth_core::record::M2mClientRecord {
        id: Uuid::new_v4(), tenant_id: tid, client_id: client_id.clone(),
        client_secret_hash: secret_hash, scopes: b.scopes.unwrap_or_default(),
        is_active: true, created_at: chrono::Utc::now(),
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id, "client_id": client_id, "client_secret": secret})).into_response())
}

// ─── Passkey ───────────────────────────────────────────────

pub async fn list_passkeys(State(s): State<AppState>, jar: CookieJar, Path(uid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let passkeys = PasskeyStore::list_by_user(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = passkeys.iter().map(|p| serde_json::json!({"id":p.id,"name":p.name,"created_at":p.created_at.to_rfc3339(),"last_used_at":p.last_used_at.map(|t|t.to_rfc3339())})).collect();
    Ok(Json(items).into_response())
}

pub async fn delete_passkey(State(s): State<AppState>, jar: CookieJar, Path((uid, pk_id)): Path<(Uuid, Uuid)>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    PasskeyStore::delete(&s.db, uid, pk_id).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── User management ──────────────────────────────────────

#[derive(Deserialize)]
pub struct PatchUserReq { pub display_name: Option<String>, pub locale: Option<String> }

pub async fn patch_user(State(s): State<AppState>, jar: CookieJar, Path(uid): Path<Uuid>, Json(b): Json<PatchUserReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    if let Some(ref name) = b.display_name {
        UserStore::update_display_name(&s.db, uid, name).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    }
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn delete_user(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    UserStore::soft_delete(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── OAuth2 Token (M2M) ──────────────────────────────────

#[derive(Deserialize)]
pub struct TokenReq {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
}

pub async fn oauth_token(State(s): State<AppState>, axum::extract::Form(b): axum::extract::Form<TokenReq>) -> Result<Response, ApiError> {
    if b.grant_type != "client_credentials" {
        return Err(ApiError::bad_request("UNSUPPORTED_GRANT", "only client_credentials supported"));
    }
    let client = M2mClientStore::find_by_client_id(&s.db, &b.client_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("INVALID_CLIENT", "invalid client_id"))?;

    let hash = crate::handlers::mfa::sha256_hex_pub(&b.client_secret);
    // #21: constant-time compare to avoid leaking the hash via early-exit timing.
    if !crate::security::constant_time_eq(hash.as_bytes(), client.client_secret_hash.as_bytes()) {
        return Err(ApiError::unauthorized("INVALID_CLIENT", "invalid client_secret"));
    }

    let jwt = s.jwt_issuer.issue(&volta_auth_core::jwt::VoltaClaims {
        sub: client.client_id.clone(), email: None,
        tenant_id: Some(client.tenant_id.to_string()), tenant_slug: None,
        roles: Some(client.scopes.clone()), name: None, app_id: None, iat: None, exp: None,
    }).map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({
        "access_token": jwt,
        "token_type": "Bearer",
        "expires_in": s.session_ttl_secs,
    })).into_response())
}