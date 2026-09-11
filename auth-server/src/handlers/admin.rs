//! Admin API handlers — audit, devices, billing, policies, SCIM, admin users/tenants.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::helpers::{require_admin_with_headers, require_session as auth};
use crate::state::AppState;
use volta_auth_core::store::*;

/// Thin wrapper to keep handler bodies tidy — Bearer-or-cookie admin auth.
async fn auth_admin(
    s: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
) -> Result<volta_auth_core::record::SessionRecord, ApiError> {
    require_admin_with_headers(s, jar, Some(headers)).await
}

// ─── Audit ─────────────────────────────────────────────────

pub async fn list_audit(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<crate::pagination::PageRequest>,
) -> Result<Response, ApiError> {
    let session = auth_admin(&s, &jar, &headers).await?;
    let req = q.normalized();
    let tid: Uuid = session.tenant_id.parse().unwrap_or_default();
    let from = req
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let to = req
        .to
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&chrono::Utc));
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["timestamp", "event_type"],
        "timestamp DESC",
    );
    let (items, total) =
        s.db.list_audit_paginated(
            tid,
            from,
            to,
            req.event.as_deref(),
            &order,
            req.limit(),
            req.offset(),
        )
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let resp = crate::pagination::PageResponse::new(items, total, &req);
    Ok(Json(resp).into_response())
}

// ─── Devices ───────────────────────────────────────────────

pub async fn list_devices(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    let devices = DeviceTrustStore::list_trusted(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = devices.iter().map(|d| serde_json::json!({
        "id":d.id,"device_id":d.device_id,"device_name":d.device_name,"last_seen_at":d.last_seen_at.to_rfc3339()
    })).collect();
    Ok(Json(items).into_response())
}

pub async fn delete_device(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(device_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    DeviceTrustStore::delete_trusted(&s.db, uid, device_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn delete_all_devices(
    State(s): State<AppState>,
    jar: CookieJar,
) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    DeviceTrustStore::delete_all_trusted(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Billing ───────────────────────────────────────────────

pub async fn get_billing(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let plans = BillingStore::list_plans(&s.db)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let sub = BillingStore::find_subscription(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"plans": plans.iter().map(|p| serde_json::json!({"id":p.id,"name":p.name,"max_members":p.max_members})).collect::<Vec<_>>(), "subscription": sub.map(|s| serde_json::json!({"plan_id":s.plan_id,"status":s.status}))})).into_response())
}

#[derive(Deserialize)]
pub struct SubscriptionReq {
    pub plan_id: String,
}

pub async fn upsert_subscription(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<SubscriptionReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let id = BillingStore::upsert_subscription(
        &s.db,
        volta_auth_core::record::SubscriptionRecord {
            id: Uuid::new_v4(),
            tenant_id: tid,
            plan_id: b.plan_id,
            status: "active".into(),
            stripe_sub_id: None,
            started_at: chrono::Utc::now(),
            expires_at: None,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

// ─── Policy ────────────────────────────────────────────────

pub async fn list_policies(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let policies = PolicyStore::list_by_tenant(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = policies.iter().map(|p| serde_json::json!({
        "id":p.id,"resource":p.resource,"action":p.action,"effect":p.effect,"priority":p.priority
    })).collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
pub struct CreatePolicyReq {
    pub resource: String,
    pub action: String,
    pub effect: Option<String>,
    pub priority: Option<i32>,
    pub condition: Option<serde_json::Value>,
}

pub async fn create_policy(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<CreatePolicyReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let id = PolicyStore::create(
        &s.db,
        volta_auth_core::record::PolicyRecord {
            id: Uuid::new_v4(),
            tenant_id: tid,
            resource: b.resource,
            action: b.action,
            condition: b.condition.unwrap_or(serde_json::json!({})),
            effect: b.effect.unwrap_or_else(|| "allow".into()),
            priority: b.priority.unwrap_or(0),
            is_active: true,
            created_at: chrono::Utc::now(),
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

#[derive(Deserialize)]
pub struct EvaluatePolicyReq {
    pub resource: String,
    pub action: String,
}

pub async fn evaluate_policy(
    State(s): State<AppState>,
    jar: CookieJar,
    Path(tid): Path<Uuid>,
    Json(b): Json<EvaluatePolicyReq>,
) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let policy = PolicyStore::find_matching(&s.db, tid, &b.resource, &b.action)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let effect = policy.map(|p| p.effect).unwrap_or_else(|| "deny".into());
    Ok(Json(serde_json::json!({"effect": effect})).into_response())
}

// ─── GDPR ──────────────────────────────────────────────────

pub async fn data_export(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session
        .user_id
        .parse()
        .map_err(|_| ApiError::internal("bad uid"))?;
    let user = UserStore::find_by_id(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let tenants = TenantStore::find_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let sessions = SessionStore::list_by_user(&s.db, &session.user_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({
        "user": user.map(|u| serde_json::json!({"id":u.id,"email":u.email,"display_name":u.display_name})),
        "tenants": tenants.iter().map(|t| serde_json::json!({"id":t.id,"name":t.name,"slug":t.slug})).collect::<Vec<_>>(),
        "sessions_count": sessions.len(),
    })).into_response())
}

pub async fn hard_delete_user(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(uid): Path<Uuid>,
) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar, &headers).await?;
    // #18 GDPR hard delete must cover:
    //   - audit_logs         (anonymize actor_id + detail)
    //   - outbox_events      (delete any pending event that names this user)
    //   - auth_flow_transitions (delete PII-bearing context_snapshots)
    //   - users              (soft delete — real rows retained for FK integrity)
    AuditStore::anonymize(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    OutboxStore::delete_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    AuditStore::delete_flow_transitions_by_user(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    UserStore::soft_delete(&s.db, uid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Admin system ──────────────────────────────────────────

pub async fn admin_list_tenants(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<crate::pagination::PageRequest>,
) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar, &headers).await?;
    let req = q.normalized();
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["created_at", "name", "slug"],
        "created_at DESC",
    );
    let (items, total) =
        s.db.list_tenants_paginated(req.q.as_deref(), &order, req.limit(), req.offset())
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

pub async fn admin_list_users(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(q): Query<crate::pagination::PageRequest>,
) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar, &headers).await?;
    let req = q.normalized();
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["email", "created_at", "display_name"],
        "created_at DESC",
    );
    let (items, total) =
        s.db.list_users_paginated(req.q.as_deref(), &order, req.limit(), req.offset())
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

#[derive(Deserialize)]
pub struct AdminCreateUserReq {
    pub tenant_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
}

#[derive(Debug)]
struct NormalizedUser {
    email: String,
    display_name: Option<String>,
    role: String,
}

fn normalize_new_user(
    email: &str,
    display_name: Option<&str>,
    role: &str,
) -> Result<NormalizedUser, ApiError> {
    let email = email.trim().to_ascii_lowercase();
    let valid_email = email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
    });
    if !valid_email || email.chars().count() > 255 {
        return Err(ApiError::bad_request(
            "INVALID_EMAIL",
            "有効なメールアドレスを指定してください",
        ));
    }

    let display_name = display_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    if display_name
        .as_ref()
        .is_some_and(|name| name.chars().count() > 100)
    {
        return Err(ApiError::bad_request(
            "INVALID_DISPLAY_NAME",
            "表示名は100文字以内にしてください",
        ));
    }

    // OWNER の追加は ownership transfer と意味が衝突するため、この入口では扱わない。
    let role = role.trim().to_ascii_uppercase();
    if !["ADMIN", "OPERATOR", "MEMBER", "VIEWER"].contains(&role.as_str()) {
        return Err(ApiError::bad_request(
            "INVALID_ROLE",
            "role は ADMIN / OPERATOR / MEMBER / VIEWER のいずれかにしてください",
        ));
    }

    Ok(NormalizedUser {
        email,
        display_name,
        role,
    })
}

/// 管理画面からユーザーを事前登録し、指定テナントの membership も同時に作る。
///
/// OIDC 初回ログイン時は検証済み email で既存ユーザーを引き継ぐため、ここでは
/// IdP subject を捏造しない。ユーザーと membership は同一 transaction に閉じる。
pub async fn admin_create_user(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(body): Json<AdminCreateUserReq>,
) -> Result<Response, ApiError> {
    let actor = auth_admin(&s, &jar, &headers).await?;
    let user = normalize_new_user(&body.email, body.display_name.as_deref(), &body.role)?;
    // Bearer 管理トークンは user ではなく M2M client を subject にできる。
    // memberships.invited_by は users への外部キーなので、その場合は空にする。
    let actor_id = if actor.session_id.starts_with("m2m-") {
        None
    } else {
        Some(Uuid::parse_str(&actor.user_id).map_err(|_| ApiError::internal("bad actor id"))?)
    };

    let mut tx =
        s.db.pool()
            .begin()
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;

    let tenant_active =
        sqlx::query_scalar::<_, bool>("SELECT is_active FROM tenants WHERE id = $1")
            .bind(body.tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?
            .ok_or_else(|| ApiError::bad_request("TENANT_NOT_FOUND", "テナントが見つかりません"))?;
    if !tenant_active {
        return Err(ApiError::bad_request(
            "TENANT_INACTIVE",
            "停止中のテナントにはユーザーを追加できません",
        ));
    }

    let user_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users (email, display_name, google_sub, is_active, locale, deleted_at) \
         VALUES ($1, $2, NULL, true, 'ja', NULL) \
         ON CONFLICT (email) DO UPDATE SET \
           display_name = COALESCE(EXCLUDED.display_name, users.display_name), \
           is_active = true, deleted_at = NULL \
         RETURNING id",
    )
    .bind(&user.email)
    .bind(&user.display_name)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    let membership_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO memberships (user_id, tenant_id, role, invited_by, is_active) \
         VALUES ($1, $2, $3, $4, true) \
         ON CONFLICT (user_id, tenant_id) DO UPDATE SET \
           role = EXCLUDED.role, invited_by = EXCLUDED.invited_by, is_active = true \
         RETURNING id",
    )
    .bind(user_id)
    .bind(body.tenant_id)
    .bind(&user.role)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    sqlx::query(
        "INSERT INTO audit_logs \
         (event_type, actor_id, tenant_id, target_type, target_id, detail, request_id) \
         VALUES ('admin.user.upserted', $1, $2, 'user', $3, $4, $5)",
    )
    .bind(actor_id)
    .bind(body.tenant_id)
    .bind(user_id.to_string())
    .bind(serde_json::json!({"email": user.email, "role": user.role}))
    .bind(Uuid::new_v4())
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": user_id,
            "membership_id": membership_id,
            "tenant_id": body.tenant_id,
            "email": user.email,
            "role": user.role,
        })),
    )
        .into_response())
}

pub async fn outbox_flush(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar, &headers).await?;
    let pending = OutboxStore::claim_pending(&s.db, 100)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    for event in &pending {
        OutboxStore::mark_published(&s.db, event.id)
            .await
            .map_err(|e| ApiError::internal(&e.to_string()))?;
    }
    Ok(Json(serde_json::json!({"flushed": pending.len()})).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_user_input_is_trimmed_and_normalized() {
        let user = normalize_new_user(" Admin@Example.COM ", Some("  管理 太郎  "), "member")
            .expect("valid input");
        assert_eq!(user.email, "admin@example.com");
        assert_eq!(user.display_name.as_deref(), Some("管理 太郎"));
        assert_eq!(user.role, "MEMBER");
    }

    #[test]
    fn new_user_rejects_invalid_email_and_owner_role() {
        let email_error = normalize_new_user("broken", None, "MEMBER").unwrap_err();
        assert_eq!(email_error.code, "INVALID_EMAIL");

        let role_error = normalize_new_user("user@example.com", None, "OWNER").unwrap_err();
        assert_eq!(role_error.code, "INVALID_ROLE");
    }

    #[test]
    fn new_user_accepts_every_assignable_non_owner_role() {
        for role in ["ADMIN", "OPERATOR", "MEMBER", "VIEWER"] {
            assert_eq!(
                normalize_new_user("user@example.com", None, role)
                    .expect("assignable role")
                    .role,
                role
            );
        }
    }
}
