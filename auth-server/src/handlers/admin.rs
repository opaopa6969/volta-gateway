//! Admin API handlers — audit, devices, billing, policies, SCIM, admin users/tenants.

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::helpers::{require_admin as auth_admin, require_session as auth};
use crate::state::AppState;
use volta_auth_core::store::*;

// ─── Audit ─────────────────────────────────────────────────

pub async fn list_audit(State(s): State<AppState>, jar: CookieJar, Query(q): Query<crate::pagination::PageRequest>) -> Result<Response, ApiError> {
    let session = auth_admin(&s, &jar).await?;
    let req = q.normalized();
    let tid: Uuid = session.tenant_id.parse().unwrap_or_default();
    let from = req.from.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Utc));
    let to = req.to.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()).map(|d| d.with_timezone(&chrono::Utc));
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(), &["timestamp", "event_type"], "timestamp DESC",
    );
    let (items, total) = s.db.list_audit_paginated(
        tid, from, to, req.event.as_deref(), &order, req.limit(), req.offset(),
    ).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let resp = crate::pagination::PageResponse::new(items, total, &req);
    Ok(Json(resp).into_response())
}

// ─── Devices ───────────────────────────────────────────────

pub async fn list_devices(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    let devices = DeviceTrustStore::list_trusted(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = devices.iter().map(|d| serde_json::json!({
        "id":d.id,"device_id":d.device_id,"device_name":d.device_name,"last_seen_at":d.last_seen_at.to_rfc3339()
    })).collect();
    Ok(Json(items).into_response())
}

pub async fn delete_device(State(s): State<AppState>, jar: CookieJar, Path(device_id): Path<Uuid>) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    DeviceTrustStore::delete_trusted(&s.db, uid, device_id).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn delete_all_devices(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    DeviceTrustStore::delete_all_trusted(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Billing ───────────────────────────────────────────────

pub async fn get_billing(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let plans = BillingStore::list_plans(&s.db).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let sub = BillingStore::find_subscription(&s.db, tid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"plans": plans.iter().map(|p| serde_json::json!({"id":p.id,"name":p.name,"max_members":p.max_members})).collect::<Vec<_>>(), "subscription": sub.map(|s| serde_json::json!({"plan_id":s.plan_id,"status":s.status}))})).into_response())
}

#[derive(Deserialize)]
pub struct SubscriptionReq { pub plan_id: String }

pub async fn upsert_subscription(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<SubscriptionReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let id = BillingStore::upsert_subscription(&s.db, volta_auth_core::record::SubscriptionRecord {
        id: Uuid::new_v4(), tenant_id: tid, plan_id: b.plan_id, status: "active".into(),
        stripe_sub_id: None, started_at: chrono::Utc::now(), expires_at: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

// ─── Policy ────────────────────────────────────────────────

pub async fn list_policies(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let policies = PolicyStore::list_by_tenant(&s.db, tid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = policies.iter().map(|p| serde_json::json!({
        "id":p.id,"resource":p.resource,"action":p.action,"effect":p.effect,"priority":p.priority
    })).collect();
    Ok(Json(items).into_response())
}

#[derive(Deserialize)]
pub struct CreatePolicyReq { pub resource: String, pub action: String, pub effect: Option<String>, pub priority: Option<i32>, pub condition: Option<serde_json::Value> }

pub async fn create_policy(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<CreatePolicyReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let id = PolicyStore::create(&s.db, volta_auth_core::record::PolicyRecord {
        id: Uuid::new_v4(), tenant_id: tid, resource: b.resource, action: b.action,
        condition: b.condition.unwrap_or(serde_json::json!({})), effect: b.effect.unwrap_or_else(|| "allow".into()),
        priority: b.priority.unwrap_or(0), is_active: true, created_at: chrono::Utc::now(),
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

#[derive(Deserialize)]
pub struct EvaluatePolicyReq { pub resource: String, pub action: String }

pub async fn evaluate_policy(State(s): State<AppState>, jar: CookieJar, Path(tid): Path<Uuid>, Json(b): Json<EvaluatePolicyReq>) -> Result<Response, ApiError> {
    let _ = auth(&s, &jar).await?;
    let policy = PolicyStore::find_matching(&s.db, tid, &b.resource, &b.action).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let effect = policy.map(|p| p.effect).unwrap_or_else(|| "deny".into());
    Ok(Json(serde_json::json!({"effect": effect})).into_response())
}

// ─── GDPR ──────────────────────────────────────────────────

pub async fn data_export(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let session = auth(&s, &jar).await?;
    let uid: Uuid = session.user_id.parse().map_err(|_| ApiError::internal("bad uid"))?;
    let user = UserStore::find_by_id(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let tenants = TenantStore::find_by_user(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    let sessions = SessionStore::list_by_user(&s.db, &session.user_id).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({
        "user": user.map(|u| serde_json::json!({"id":u.id,"email":u.email,"display_name":u.display_name})),
        "tenants": tenants.iter().map(|t| serde_json::json!({"id":t.id,"name":t.name,"slug":t.slug})).collect::<Vec<_>>(),
        "sessions_count": sessions.len(),
    })).into_response())
}

pub async fn hard_delete_user(State(s): State<AppState>, jar: CookieJar, Path(uid): Path<Uuid>) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar).await?;
    // #18 GDPR hard delete must cover:
    //   - audit_logs         (anonymize actor_id + detail)
    //   - outbox_events      (delete any pending event that names this user)
    //   - auth_flow_transitions (delete PII-bearing context_snapshots)
    //   - users              (soft delete — real rows retained for FK integrity)
    AuditStore::anonymize(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    OutboxStore::delete_by_user(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    AuditStore::delete_flow_transitions_by_user(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    UserStore::soft_delete(&s.db, uid).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

// ─── Admin system ──────────────────────────────────────────

pub async fn admin_list_tenants(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar).await?;
    // Tenant pagination is out-of-scope for Java sync (Java endpoint wasn't paginated);
    // leaving as stub until dedicated spec lands.
    Ok(Json(serde_json::json!({"tenants": []})).into_response())
}

pub async fn admin_list_users(State(s): State<AppState>, jar: CookieJar, Query(q): Query<crate::pagination::PageRequest>) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar).await?;
    let req = q.normalized();
    let order = crate::pagination::PageRequest::order_sql(
        req.sort.as_deref(),
        &["email", "created_at", "display_name"],
        "created_at DESC",
    );
    let (items, total) = s.db.list_users_paginated(
        req.q.as_deref(), &order, req.limit(), req.offset(),
    ).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(crate::pagination::PageResponse::new(items, total, &req)).into_response())
}

pub async fn outbox_flush(State(s): State<AppState>, jar: CookieJar) -> Result<Response, ApiError> {
    let _ = auth_admin(&s, &jar).await?;
    let pending = OutboxStore::claim_pending(&s.db, 100).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    for event in &pending {
        OutboxStore::mark_published(&s.db, event.id).await.map_err(|e| ApiError::internal(&e.to_string()))?;
    }
    Ok(Json(serde_json::json!({"flushed": pending.len()})).into_response())
}
