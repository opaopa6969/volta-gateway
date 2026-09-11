//! Extra handlers — admin sessions, transfer-ownership, switch-account,
//! select-tenant, user export, and the legacy settings/temporary-access HTML.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use uuid::Uuid;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{clear_session_cookie, extract_session_id, require_admin};
use crate::state::AppState;
use volta_auth_core::crypto::{random_token_hex, session_id_fingerprint, sha256_hex};
use volta_auth_core::record::TemporaryAccessGrantRecord;
use volta_auth_core::store::{MembershipStore, SessionStore, TenantStore, UserStore};

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
    let (items, total) =
        s.db.list_sessions_paginated(req.user_id.as_deref(), &order, req.limit(), req.offset())
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items = items
        .into_iter()
        .map(|mut item| {
            if let Some(object) = item.as_object_mut() {
                if let Some(serde_json::Value::String(id)) = object.remove("session_id") {
                    object.insert(
                        "session_id_hash".into(),
                        serde_json::json!(session_id_fingerprint(&id)),
                    );
                }
            }
            item
        })
        .collect();
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

/// DELETE /admin/sessions/{id} — admin revoke session.
pub async fn admin_revoke_session(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(sid): Path<String>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    let sid =
        s.db.resolve_session_reference(&sid, None)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?
            .ok_or_else(|| ApiError::bad_request("SESSION_NOT_FOUND", "session not found"))?;
    SessionStore::revoke(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

/// DELETE /auth/sessions/{id}
pub async fn revoke_session_by_id(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(sid): Path<String>,
) -> Result<Response, ApiError> {
    let _ = auth_sync(&jar)?;
    let sid =
        s.db.resolve_session_reference(&sid, None)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?
            .ok_or_else(|| ApiError::bad_request("SESSION_NOT_FOUND", "session not found"))?;
    SessionStore::revoke(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

/// POST /auth/sessions/revoke-all
pub async fn revoke_all_sessions(
    State(s): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let sid = auth_sync(&jar)?;
    let session = SessionStore::find(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let count = SessionStore::revoke_all_for_user(&s.db, &session.user_id)
        .await
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
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<TransferReq>,
) -> Result<Response, ApiError> {
    let sid = auth_sync(&jar)?;
    let session = SessionStore::find(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let from_uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;

    // Demote current owner to ADMIN, promote target to OWNER
    let from_m = MembershipStore::find(&s.db, from_uid, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::forbidden("TENANT_ACCESS_DENIED", "not a member"))?;
    MembershipStore::update_role(&s.db, from_m.id, "ADMIN")
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    let to_m = MembershipStore::find(&s.db, b.to_user_id, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "target user not a member"))?;
    MembershipStore::update_role(&s.db, to_m.id, "OWNER")
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Switch Account ────────────────────────────────────────

/// POST /auth/switch-account — re-authenticate (redirect to login).
pub async fn switch_account(
    State(s): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    // Revoke current session and redirect to login
    if let Some(sid) = extract_session_id(&jar) {
        let _ = SessionStore::revoke(&s.db, &sid).await;
    }
    let mut resp =
        Json(serde_json::json!({"redirect_to": format!("{}/login", s.base_url)})).into_response();
    clear_session_cookie(&mut resp, &s);
    no_cache_headers(&mut resp);
    Ok(resp)
}

// ─── Select Tenant ─────────────────────────────────────────

/// GET /select-tenant
pub async fn select_tenant(
    State(s): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let sid = auth_sync(&jar)?;
    let session = SessionStore::find(&s.db, &sid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::unauthorized("SESSION_EXPIRED", "re-login"))?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    let tenants = TenantStore::find_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = tenants
        .iter()
        .map(|t| serde_json::json!({"id": t.id, "name": t.name, "slug": t.slug}))
        .collect();
    Ok(Json(serde_json::json!({"tenants": items})).into_response())
}

// ─── User Export (admin) ───────────────────────────────────

/// POST /api/v1/users/{userId}/export — admin data export for specific user.
pub async fn admin_export_user(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(uid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    let user = UserStore::find_by_id(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let tenants = TenantStore::find_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({
        "user": user.map(|u| serde_json::json!({"id":u.id,"email":u.email,"display_name":u.display_name})),
        "tenants": tenants.iter().map(|t| serde_json::json!({"id":t.id,"name":t.name})).collect::<Vec<_>>(),
    })).into_response())
}

#[derive(serde::Deserialize)]
pub struct CreateTemporaryAccessReq {
    pub tenant_id: Uuid,
    pub subject: String,
    pub role: String,
    pub domains: Vec<String>,
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    pub starts_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Creates an opaque, revocable credential. Its plaintext is returned once.
pub async fn create_temporary_access(
    State(s): State<AppState>,
    jar: CookieJar,
    Json(req): Json<CreateTemporaryAccessReq>,
) -> Result<Response, ApiError> {
    let issuer = require_admin(&s, &jar).await?;
    let role = req.role.trim().to_ascii_uppercase();
    let valid_pattern = |d: &String| {
        if d == "*" {
            return true;
        }
        let plain = d.strip_prefix("*.").unwrap_or(d);
        !plain.is_empty() && !plain.contains('/') && !plain.contains(':') && plain.contains('.')
    };
    let error = if !["ADMIN", "MEMBER", "VIEWER"].contains(&role.as_str()) {
        Some("role は ADMIN / MEMBER / VIEWER のいずれかにしてください")
    } else if req.subject.trim().is_empty() {
        Some("subject を指定してください")
    } else if req.domains.is_empty() || !req.domains.iter().all(valid_pattern) {
        Some("allowlist domain は host、*.example.com、または * で指定してください")
    } else if !req.blocked_domains.iter().all(valid_pattern) {
        Some("blocklist domain は host、*.example.com、または * で指定してください")
    } else if req.starts_at >= req.expires_at {
        Some("終了時刻は開始時刻より後にしてください")
    } else if req.expires_at > chrono::Utc::now() + chrono::Duration::days(30) {
        Some("有効期間は30日以内にしてください")
    } else {
        None
    };
    if let Some(message) = error {
        return Err(ApiError::bad_request("INVALID_TEMPORARY_ACCESS", message));
    }
    let created_by = issuer
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad issuer"))?;
    let bearer = format!("vta_{}", random_token_hex(32));
    let grant = TemporaryAccessGrantRecord {
        id: Uuid::new_v4(),
        tenant_id: req.tenant_id,
        token_hash: sha256_hex(&bearer),
        subject: req.subject.trim().to_string(),
        role,
        domains: req.domains,
        blocked_domains: req.blocked_domains,
        starts_at: req.starts_at,
        expires_at: req.expires_at,
        created_by,
        created_at: chrono::Utc::now(),
        revoked_at: None,
    };
    s.db.create_temporary_access_grant(&grant)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": grant.id, "bearer": bearer})).into_response())
}

#[derive(serde::Deserialize)]
pub struct TemporaryAccessListQuery {
    pub tenant_id: Uuid,
}

pub async fn list_temporary_access(
    State(s): State<AppState>,
    jar: CookieJar,
    Query(q): Query<TemporaryAccessListQuery>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    let grants =
        s.db.list_temporary_access_grants(q.tenant_id)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    let values: Vec<_> = grants.into_iter().map(|g| serde_json::json!({"id":g.id,"subject":g.subject,"role":g.role,"domains":g.domains,"blocked_domains":g.blocked_domains,"starts_at":g.starts_at,"expires_at":g.expires_at,"revoked_at":g.revoked_at})).collect();
    Ok(Json(values).into_response())
}

pub async fn revoke_temporary_access(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = require_admin(&s, &jar).await?;
    s.db.revoke_temporary_access_grant(id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok":true})).into_response())
}

#[allow(dead_code)] // Kept as a rollback fallback; /admin/temporary-access uses admin_ui.
pub async fn temporary_access_page() -> Response {
    let mut response = temporary_access_page_html();
    no_cache_headers(&mut response);
    response
}

#[allow(dead_code)]
fn temporary_access_page_html() -> Response {
    Html(r#"<!doctype html><html lang="ja"><meta charset="utf-8"><title>一時アクセス</title><style>body{font-family:system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}label,input,select,button{display:block;width:100%;box-sizing:border-box;margin:.45rem 0;padding:.65rem}#result{margin-top:1rem;padding:1rem;background:#f4f4f4;word-break:break-all}.hidden{display:none}</style><h1>一時アクセスを発行</h1><form id="grant"><label>Tenant<select id="tenant" name="tenant_id" required></select></label><label>Subject<input name="subject" placeholder="user@example.com / program:name" required></label><label>Role<select name="role"><option>MEMBER</option><option>VIEWER</option><option>ADMIN</option></select></label><label>許可 domain<input name="domains" placeholder="kamishibai.unlaxer.org, *.unlaxer.org" required></label><label>除外 domain<input name="blocked_domains"></label><label>期間<select id="period"><option value="relative" selected>今からの時間</option><option value="absolute">開始・終了日時</option></select></label><div id="relative"><label>開始まで（時間）<input id="startHours" type="number" min="0" value="0"></label><label>有効時間<input id="durationHours" type="number" min="1" value="24"></label></div><div id="absolute" class="hidden"><label>開始<input id="startsAt" type="datetime-local"></label><label>終了<input id="expiresAt" type="datetime-local"></label></div><button>発行</button></form><div id="result" aria-live="polite"></div><script>const $=s=>document.querySelector(s),split=s=>s.split(',').map(x=>x.trim()).filter(Boolean),show=t=>$('#result').textContent=t;fetch('/select-tenant',{credentials:'include'}).then(r=>r.ok?r.json():Promise.reject(r.status)).then(d=>{$('#tenant').innerHTML=(d.tenants||[]).map(t=>`<option value="${t.id}">${t.name} (${t.slug})</option>`).join('');if(!d.tenants?.length)show('利用できる tenant がありません。');}).catch(e=>show('tenant の取得に失敗しました: '+e));$('#period').onchange=()=>{let a=$('#period').value==='absolute';$('#absolute').classList.toggle('hidden',!a);$('#relative').classList.toggle('hidden',a);$('#startsAt').required=a;$('#expiresAt').required=a};$('#grant').onsubmit=async e=>{e.preventDefault();let x=Object.fromEntries(new FormData(e.currentTarget)),now=Date.now();if($('#period').value==='relative'){x.starts_at=new Date(now+(+$('#startHours').value||0)*3600000).toISOString();x.expires_at=new Date(new Date(x.starts_at).getTime()+(+$('#durationHours').value||0)*3600000).toISOString()}else{x.starts_at=new Date($('#startsAt').value).toISOString();x.expires_at=new Date($('#expiresAt').value).toISOString()}x.domains=split(x.domains);x.blocked_domains=split(x.blocked_domains);try{let r=await fetch('/api/v1/temporary-access',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(x)}),d=await r.json();if(!r.ok)throw new Error(d?.error?.message||JSON.stringify(d));let target=x.domains[0].replace(/^\*\./,'app.'),link=location.origin+'/temporary-access/activate?token='+encodeURIComponent(d.bearer)+'&return_to='+encodeURIComponent('https://'+target+'/'),box=$('#result');box.replaceChildren();for(const [label,value] of [['Bearer','Authorization: Bearer '+d.bearer],['Link',link]]){let h=document.createElement('strong'),v=document.createElement(label==='Link'?'a':'code'),copy=document.createElement('button');h.textContent=label;v.textContent=value;if(label==='Link'){v.href=link;v.target='_blank';v.rel='noreferrer'}copy.type='button';copy.textContent='コピー';copy.onclick=()=>navigator.clipboard.writeText(value);box.append(h,v,copy,document.createElement('br'));}}catch(err){show('発行に失敗しました: '+err.message)}};</script></html>"#.to_string()).into_response()
}

#[allow(dead_code)]
fn temporary_access_page_html_v1() -> Response {
    Html(r#"<!doctype html><html lang="ja"><meta charset="utf-8"><title>一時アクセス</title><style>body{font-family:system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}label,input,select,button{display:block;width:100%;box-sizing:border-box;margin:.45rem 0;padding:.65rem}pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem}.hidden{display:none}</style><h1>一時アクセスを発行</h1><form id="grant"><label>Tenant<select id="tenant" name="tenant_id" required></select></label><label>Subject<input name="subject" placeholder="user@example.com / program:name" required></label><label>Role<select name="role"><option>MEMBER</option><option>VIEWER</option><option>ADMIN</option></select></label><label>許可 domain<input name="domains" placeholder="kamishibai.unlaxer.org, *.unlaxer.org" required></label><label>除外 domain<input name="blocked_domains" placeholder="admin.unlaxer.org"></label><label>期間方式<select id="period"><option value="relative" selected>今からの時間</option><option value="absolute">開始・終了日時</option></select></label><div id="relative"><label>開始まで（時間）<input id="startHours" type="number" min="0" value="0"></label><label>有効時間<input id="durationHours" type="number" min="1" value="24"></label></div><div id="absolute" class="hidden"><label>開始<input id="startsAt" type="datetime-local"></label><label>終了<input id="expiresAt" type="datetime-local"></label></div><button>発行</button></form><pre id="output" aria-live="polite"></pre><script>const $=s=>document.querySelector(s),split=s=>s.split(',').map(x=>x.trim()).filter(Boolean);fetch('/select-tenant',{credentials:'include'}).then(r=>r.ok?r.json():Promise.reject(r.status)).then(d=>{$('#tenant').innerHTML=(d.tenants||[]).map(t=>`<option value="${t.id}">${t.name} (${t.slug})</option>`).join('');if(!d.tenants?.length)$('#output').textContent='利用できる tenant がありません。';}).catch(e=>$('#output').textContent='tenant の取得に失敗しました: '+e);$('#period').onchange=()=>{let a=$('#period').value==='absolute';$('#absolute').classList.toggle('hidden',!a);$('#relative').classList.toggle('hidden',a);$('#startsAt').required=a;$('#expiresAt').required=a};$('#grant').onsubmit=async e=>{e.preventDefault();let x=Object.fromEntries(new FormData(e.currentTarget)),now=Date.now();if($('#period').value==='relative'){x.starts_at=new Date(now+(+$('#startHours').value||0)*3600000).toISOString();x.expires_at=new Date(new Date(x.starts_at).getTime()+(+$('#durationHours').value||0)*3600000).toISOString()}else{x.starts_at=new Date($('#startsAt').value).toISOString();x.expires_at=new Date($('#expiresAt').value).toISOString()}x.domains=split(x.domains);x.blocked_domains=split(x.blocked_domains);try{let r=await fetch('/api/v1/temporary-access',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(x)}),d=await r.json();if(!r.ok)throw new Error(d?.error?.message||JSON.stringify(d));let target=x.domains[0].replace(/^\*\./,'app.'),link=location.origin+'/temporary-access/activate?token='+encodeURIComponent(d.bearer)+'&return_to='+encodeURIComponent('https://'+target+'/');$('#output').textContent='Bearer\\nAuthorization: Bearer '+d.bearer+'\\n\\nLink\\n'+link;}catch(err){$('#output').textContent='発行に失敗しました: '+err.message}};</script></html>"#.to_string()).into_response()
}

#[allow(dead_code)]
fn temporary_access_page_previous() -> Response {
    Html(r#"<!doctype html><html lang="ja"><meta charset="utf-8"><title>一時アクセス</title><style>body{font-family:system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}input,select{width:100%;padding:.65rem;margin:.3rem 0}button{padding:.7rem 1rem}pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem}.relative{display:none}</style><h1>一時アクセスを発行</h1><p>subject はメールアドレスまたは <code>program:kamishibai-bot</code> のようなプログラム識別子です。</p><form id=f><label>Tenant<select name=tenant_id id=tenant required></select></label><label>Subject<input name=subject placeholder="user@example.com または program:name" required></label><label>Role<select name=role><option>MEMBER</option><option>VIEWER</option><option>ADMIN</option></select></label><label>許可 domain（allowlist、<code>*.unlaxer.org</code> 可）<input name=domains required></label><label>除外 domain（blocklist、任意）<input name=blocked_domains></label><label>期間入力<select id=mode><option value=absolute>開始・終了日時</option><option value=relative>今からの期間</option></select></label><span id=absolute><label>開始<input name=starts_at type=datetime-local required></label><label>終了<input name=expires_at type=datetime-local required></label></span><span id=relative class=relative><label>開始までの時間<input id=start_hours type=number min=0 value=0></label><label>有効時間<input id=duration_hours type=number min=1 value=24></label></span><button>一時アクセスを発行</button></form><pre id=o></pre><script>const split=s=>s.split(',').map(x=>x.trim()).filter(Boolean),abs=document.querySelector('#absolute'),rel=document.querySelector('#relative');mode.onchange=()=>{let r=mode.value==='relative';rel.style.display=r?'block':'none';abs.style.display=r?'none':'block'};fetch('/select-tenant',{credentials:'include'}).then(r=>r.json()).then(d=>tenant.innerHTML=(d.tenants||[]).map(t=>'<option value="'+t.id+'">'+t.name+' ('+t.slug+')</option>').join(''));f.onsubmit=async e=>{e.preventDefault();let x=Object.fromEntries(new FormData(f)),now=Date.now();if(mode.value==='relative'){x.starts_at=new Date(now+(+start_hours.value||0)*3600000).toISOString();x.expires_at=new Date(new Date(x.starts_at).getTime()+(+duration_hours.value||0)*3600000).toISOString()}else{x.starts_at=new Date(x.starts_at).toISOString();x.expires_at=new Date(x.expires_at).toISOString()}x.domains=split(x.domains);x.blocked_domains=split(x.blocked_domains);let r=await fetch('/api/v1/temporary-access',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(x)});if(!r.ok){o.textContent='発行に失敗しました。';return}let d=await r.json(),link=location.origin+'/temporary-access/activate?token='+encodeURIComponent(d.bearer)+'&return_to='+encodeURIComponent('https://'+x.domains[0].replace(/^\*\./,'app.')+'/');o.textContent='Bearer\\nAuthorization: Bearer '+d.bearer+'\\n\\nLink\\n'+link;};</script></html>"#.to_string()).into_response()
}

#[allow(dead_code)]
fn temporary_access_page_legacy() -> Response {
    Html(r#"<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>一時アクセス — Volta Auth</title><style>body{font-family:system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}input,select{width:100%;padding:.65rem;margin:.3rem 0}button{padding:.7rem 1rem}pre{white-space:pre-wrap;background:#f4f4f4;padding:1rem}</style><h1>一時アクセスを発行</h1><p>role、許可 domain、開始・終了時刻を指定します。token はこの画面で一度だけ表示されます。</p><form id=f><input name=tenant_id placeholder="Tenant UUID" required><input name=subject type=email placeholder="利用者のメールアドレス" required><select name=role><option>MEMBER</option><option>VIEWER</option><option>ADMIN</option></select><input name=domains placeholder="許可 domain（例: kamishibai.unlaxer.org、複数はカンマ区切り）" required><label>開始<input name=starts_at type=datetime-local required></label><label>終了<input name=expires_at type=datetime-local required></label><button>一時アクセスを発行</button></form><pre id=o></pre><script>f.onsubmit=async e=>{e.preventDefault();let x=Object.fromEntries(new FormData(f));x.domains=x.domains.split(',').map(v=>v.trim()).filter(Boolean);x.starts_at=new Date(x.starts_at).toISOString();x.expires_at=new Date(x.expires_at).toISOString();let r=await fetch('/api/v1/temporary-access',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(x)});if(!r.ok){o.textContent='発行に失敗しました。';return}let d=await r.json(),link=location.origin+'/temporary-access/activate?token='+encodeURIComponent(d.bearer)+'&return_to='+encodeURIComponent('https://'+x.domains[0]+'/');o.textContent='Bearer\\nAuthorization: Bearer '+d.bearer+'\\n\\nLink\\n'+link;};</script></html>"#.to_string()).into_response()
}

#[derive(serde::Deserialize)]
pub struct ActivateTemporaryAccessQuery {
    pub token: String,
    pub return_to: String,
}

/// Link form of a temporary credential. The raw token is exchanged for an
/// HttpOnly parent-domain cookie and immediately removed from the address bar.
pub async fn activate_temporary_access(
    State(s): State<AppState>,
    Query(q): Query<ActivateTemporaryAccessQuery>,
) -> Response {
    let parsed = match url::Url::parse(&q.return_to) {
        Ok(url) if url.scheme() == "https" && url.path().starts_with('/') => url,
        _ => {
            return ApiError::bad_request("INVALID_RETURN_TO", "invalid return URL").into_response()
        }
    };
    let Some(host) = parsed.host_str() else {
        return ApiError::bad_request("INVALID_RETURN_TO", "invalid return URL").into_response();
    };
    let grant =
        s.db.find_temporary_access_by_hash(&sha256_hex(&q.token))
            .await
            .ok()
            .flatten();
    let Some(grant) = grant.filter(|g| g.is_active_for(host, chrono::Utc::now())) else {
        return ApiError::forbidden("TEMPORARY_ACCESS_DENIED", "temporary access is unavailable")
            .into_response();
    };
    let seconds = (grant.expires_at - chrono::Utc::now()).num_seconds().max(1);
    let mut response = Redirect::to(parsed.as_str()).into_response();
    response.headers_mut().append(
        "set-cookie",
        format!("__volta_temporary_access={}; Path=/; Domain=.unlaxer.org; Max-Age={}; HttpOnly; Secure; SameSite=Lax", q.token, seconds).parse().unwrap(),
    );
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    no_cache_headers(&mut response);
    response
}

#[derive(serde::Deserialize)]
pub struct ExchangeTemporaryAccessReq {
    pub return_to: String,
}

/// Exchange a Bearer credential for the same HttpOnly cookie used by Link.
/// The caller must provide the credential in an Authorization header; it is
/// never accepted in a URL or copied into the response body.
pub async fn exchange_temporary_access(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ExchangeTemporaryAccessReq>,
) -> Response {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|v| v.starts_with("vta_"));
    let Some(token) = token else {
        return ApiError::unauthorized("INVALID_TOKEN", "temporary access Bearer required")
            .into_response();
    };
    let parsed = match url::Url::parse(&req.return_to) {
        Ok(url) if url.scheme() == "https" && url.path().starts_with('/') => url,
        _ => {
            return ApiError::bad_request("INVALID_RETURN_TO", "invalid return URL").into_response()
        }
    };
    let Some(host) = parsed.host_str() else {
        return ApiError::bad_request("INVALID_RETURN_TO", "invalid return URL").into_response();
    };
    let grant =
        s.db.find_temporary_access_by_hash(&sha256_hex(token))
            .await
            .ok()
            .flatten();
    let Some(grant) = grant.filter(|g| g.is_active_for(host, chrono::Utc::now())) else {
        return ApiError::forbidden("TEMPORARY_ACCESS_DENIED", "temporary access is unavailable")
            .into_response();
    };
    let seconds = (grant.expires_at - chrono::Utc::now()).num_seconds().max(1);
    let mut response = Json(serde_json::json!({"redirect_to": parsed.as_str()})).into_response();
    response.headers_mut().append(
        "set-cookie",
        format!("__volta_temporary_access={}; Path=/; Domain=.unlaxer.org; Max-Age={}; HttpOnly; Secure; SameSite=Lax", token, seconds).parse().unwrap(),
    );
    no_cache_headers(&mut response);
    response
}

// ─── Admin HTML Pages (stubs) ──────────────────────────────

fn admin_layout(title: &str, api_url: &str, columns: &[&str]) -> Response {
    let cols_header: String = columns.iter().map(|c| format!("<th>{}</th>", c)).collect();
    let cols_js: String = columns
        .iter()
        .map(|c| format!("td(row.{} != null ? row.{} : '-')", c, c))
        .collect::<Vec<_>>()
        .join("+");

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
const esc = s => String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
const td = v => '<td>'+esc(typeof v==='object'?JSON.stringify(v):v)+'</td>';
fetch('{api_url}',{{credentials:'include'}}).then(r=>r.json()).then(data=>{{
  const rows = Array.isArray(data)?data:(data.tenants||data.users||data.sessions||[]);
  if(!rows.length){{document.getElementById('data').innerHTML='<tr><td colspan=99 class="empty">No data</td></tr>';return;}}
  document.getElementById('data').innerHTML=rows.map(row=>'<tr>'+{cols_js}+'</tr>').join('');
}}).catch(e=>document.getElementById('data').innerHTML='<tr><td colspan=99 class="empty">Error</td></tr>');
</script></body></html>"##,
    )).into_response()
}

pub async fn admin_members_page() -> Response {
    admin_layout("Members", "/api/v1/admin/tenants", &["id", "name", "slug"])
}
pub async fn admin_sessions_page() -> Response {
    admin_layout(
        "Sessions",
        "/api/me/sessions",
        &[
            "session_id_hash",
            "ip_address",
            "user_agent",
            "created_at",
            "current",
        ],
    )
}
