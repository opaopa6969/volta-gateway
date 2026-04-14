//! Extra handlers — admin sessions, transfer-ownership, switch-account,
//! select-tenant, user export, admin HTML pages (stubs).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use uuid::Uuid;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{extract_session_id, clear_session_cookie, require_admin};
use crate::state::AppState;
use volta_auth_core::store::{SessionStore, MembershipStore, UserStore, TenantStore};

fn auth_sync(jar: &CookieJar) -> Result<String, ApiError> {
    extract_session_id(jar).ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))
}

// ─── Admin Sessions ────────────────────────────────────────

/// GET /admin/sessions — list all active sessions (admin, paginated P2.1).
pub async fn admin_list_sessions(
    State(s): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(q): axum::extract::Query<crate::pagination::PageRequest>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    let req = q.normalized();
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["created_at", "expires_at"],
        "created_at DESC",
    );
    let (items, total) = s.db.list_sessions_paginated(
        req.user_id.as_deref(), &order, req.limit(), req.offset(),
    ).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

/// DELETE /admin/sessions/{id} — admin revoke session.
pub async fn admin_revoke_session(State(s): State<AppState>, jar: CookieJar, Path(sid): Path<String>) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    SessionStore::revoke(&s.db, &sid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

/// DELETE /auth/sessions/{id}
pub async fn revoke_session_by_id(State(s): State<AppState>, jar: CookieJar, Path(sid): Path<String>) -> Result<Response, ApiError> {
    let _ = auth_sync(&jar)?;
    SessionStore::revoke(&s.db, &sid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

/// POST /auth/sessions/revoke-all
pub async fn revoke_all_sessions(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let sid = auth_sync(&jar)?;
    let session = SessionStore::find(&s.db, &sid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let count = SessionStore::revoke_all_for_user(&s.db, &session.user_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true, "revoked": count})).into_response())
}

// ─── Transfer Ownership ────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct TransferReq {
    #[serde(rename = "toUserId")]
    pub to_user_id: Uuid,
}

/// POST /api/v1/tenants/{tenantId}/transfer-ownership
pub async fn transfer_ownership(
    State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<TransferReq>,
) -> Result<Response, ApiError> {
    let sid = auth_sync(&jar)?;
    let session = SessionStore::find(&s.db, &sid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let from_uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;

    // Demote current owner to ADMIN, promote target to OWNER
    let from_m = MembershipStore::find(&s.db, from_uid, tid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::forbidden("TENANT_ACCESS_DENIED", "not a member"))?;
    MembershipStore::update_role(&s.db, from_m.id, "ADMIN").await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let to_m = MembershipStore::find(&s.db, b.to_user_id, tid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "target user not a member"))?;
    MembershipStore::update_role(&s.db, to_m.id, "OWNER").await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Switch Account ────────────────────────────────────────

/// POST /auth/switch-account — re-authenticate (redirect to login).
pub async fn switch_account(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    // Revoke current session and redirect to login
    if let Some(sid) = extract_session_id(&jar) {
        let _ = SessionStore::revoke(&s.db, &sid).await;
    }
    let mut resp = Json(serde_json::json!({"redirect_to": format!("{}/login", s.base_url)})).into_response();
    clear_session_cookie(&mut resp, &s);
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ─── Select Tenant ─────────────────────────────────────────

/// GET /select-tenant
pub async fn select_tenant(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let sid = auth_sync(&jar)?;
    let session = SessionStore::find(&s.db, &sid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    let tenants = TenantStore::find_by_user(&s.db, uid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = tenants.iter().map(|t|
        serde_json::json!({"id": t.id, "name": t.name, "slug": t.slug})
    ).collect();
    Ok(Json(serde_json::json!({"tenants": items})).into_response())
}

// ─── User Export (admin) ───────────────────────────────────

/// POST /api/v1/users/{userId}/export — admin data export for specific user.
pub async fn admin_export_user(State(s): State<AppState>, jar: CookieJar, Path(uid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    let user = UserStore::find_by_id(&s.db, uid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let tenants = TenantStore::find_by_user(&s.db, uid).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({
        "user": user.map(|u| serde_json::json!({"id":u.id,"email":u.email,"display_name":u.display_name})),
        "tenants": tenants.iter().map(|t| serde_json::json!({"id":t.id,"name":t.name})).collect::<Vec<_>>(),
    })).into_response())
}

// ─── Admin HTML Pages (stubs) ──────────────────────────────

fn admin_layout(title: &str, api_url: &str, columns: &[&str]) -> Response {
    let cols_header: String = columns.iter().map(|c| format!("<th>{}</th>", c)).collect();
    let cols_js: String = columns.iter().map(|c| format!(
        "td(row.{} != null ? row.{} : '-')", c, c
    )).collect::<Vec<_>>().join("+");

    Html(format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title} — volta admin</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,-apple-system,sans-serif;background:#f5f5f5;color:#333}}
nav{{background:#1a1a2e;padding:12px 24px;display:flex;gap:16px;flex-wrap:wrap}}
nav a{{color:#e0e0e0;text-decoration:none;font-size:14px;padding:4px 8px;border-radius:4px}}
nav a:hover{{background:#16213e;color:#fff}}
nav a.active{{background:#0f3460;color:#fff}}
.container{{max-width:1200px;margin:24px auto;padding:0 24px}}
h1{{font-size:24px;margin-bottom:16px}}
table{{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
th{{background:#e8e8e8;padding:10px 12px;text-align:left;font-size:13px;text-transform:uppercase;letter-spacing:.5px}}
td{{padding:10px 12px;border-top:1px solid #eee;font-size:14px}}
tr:hover td{{background:#fafafa}}
.empty{{padding:24px;text-align:center;color:#999}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;background:#e3f2fd;color:#1565c0}}
</style></head><body>
<nav>
  <a href="/admin/tenants">Tenants</a>
  <a href="/admin/users">Users</a>
  <a href="/admin/members">Members</a>
  <a href="/admin/sessions">Sessions</a>
  <a href="/admin/invitations">Invitations</a>
  <a href="/admin/webhooks">Webhooks</a>
  <a href="/admin/idp">IdP Config</a>
  <a href="/admin/audit">Audit Log</a>
</nav>
<div class="container">
<h1>{title}</h1>
<table><thead><tr>{cols_header}</tr></thead><tbody id="data"></tbody></table>
</div>
<script>
const td = v => '<td>'+(typeof v==='object'?JSON.stringify(v):v)+'</td>';
fetch('{api_url}',{{credentials:'include'}}).then(r=>r.json()).then(data=>{{
  const rows = Array.isArray(data)?data:(data.tenants||data.users||data.sessions||[]);
  if(!rows.length){{document.getElementById('data').innerHTML='<tr><td colspan=99 class="empty">No data</td></tr>';return;}}
  document.getElementById('data').innerHTML=rows.map(row=>'<tr>'+{cols_js}+'</tr>').join('');
}}).catch(e=>document.getElementById('data').innerHTML='<tr><td colspan=99 class="empty">Error: '+e+'</td></tr>');
</script></body></html>"##,
    )).into_response()
}

pub async fn admin_tenants_page() -> Response {
    admin_layout("Tenants", "/api/v1/admin/tenants", &["id", "name", "slug", "plan", "is_active"])
}
pub async fn admin_users_page() -> Response {
    admin_layout("Users", "/api/v1/admin/users", &["id", "email", "display_name", "is_active"])
}
pub async fn admin_members_page() -> Response {
    admin_layout("Members", "/api/v1/admin/tenants", &["id", "name", "slug"])
}
pub async fn admin_sessions_page() -> Response {
    admin_layout("Sessions", "/api/me/sessions", &["session_id", "ip_address", "user_agent", "created_at", "current"])
}
pub async fn admin_invitations_page() -> Response {
    admin_layout("Invitations", "/api/v1/admin/tenants", &["id", "name", "slug"])
}
pub async fn admin_webhooks_page() -> Response {
    admin_layout("Webhooks", "/api/v1/admin/tenants", &["id", "name", "slug"])
}
pub async fn admin_idp_page() -> Response {
    admin_layout("IdP Config", "/api/v1/admin/tenants", &["id", "name", "slug"])
}
pub async fn admin_audit_page() -> Response {
    admin_layout("Audit Log", "/api/v1/admin/audit", &["id", "timestamp", "event_type", "actor_id", "target_type", "target_id"])
}
