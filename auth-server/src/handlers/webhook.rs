//! Webhook + delivery handlers.

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::helpers::require_tenant_role;
use crate::security::validate_webhook_url;
use crate::state::AppState;
use volta_auth_core::store::{WebhookDeliveryStore, WebhookStore};

/// Dev override: allow `http://` and private-range webhook URLs when set to "true".
fn allow_insecure_webhooks() -> bool {
    std::env::var("VOLTA_ALLOW_INSECURE_WEBHOOKS")
        .ok()
        .as_deref()
        == Some("true")
}

/// Webhook の管理は対象テナントの ADMIN 以上。
async fn auth(
    s: &AppState,
    jar: &CookieJar,
    headers: &HeaderMap,
    tenant_id: Uuid,
) -> Result<(), ApiError> {
    require_tenant_role(s, jar, headers, tenant_id, "ADMIN").await?;
    Ok(())
}

/// wid がそのテナントの webhook であることを確かめる。
async fn webhook_in_tenant(
    s: &AppState,
    tenant_id: Uuid,
    webhook_id: Uuid,
) -> Result<volta_auth_core::record::WebhookRecord, ApiError> {
    WebhookStore::find(&s.db, tenant_id, webhook_id)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "webhook not found"))
}

#[derive(Deserialize)]
pub struct CreateWebhookReq {
    pub endpoint_url: String,
    pub events: String,
    pub secret: Option<String>,
}

pub async fn create_webhook(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(tid): Path<Uuid>,
    Json(b): Json<CreateWebhookReq>,
) -> Result<Response, ApiError> {
    auth(&s, &jar, &headers, tid).await?;
    validate_webhook_url(&b.endpoint_url, allow_insecure_webhooks())
        .map_err(|e| ApiError::bad_request("INVALID_ENDPOINT", &e))?;
    let secret = b.secret.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let id = WebhookStore::create(
        &s.db,
        volta_auth_core::record::WebhookRecord {
            id: Uuid::new_v4(),
            tenant_id: tid,
            endpoint_url: b.endpoint_url,
            secret,
            events: b.events,
            is_active: true,
            created_at: chrono::Utc::now(),
            last_success_at: None,
            last_failure_at: None,
        },
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"id": id})).into_response())
}

pub async fn list_webhooks(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path(tid): Path<Uuid>,
) -> Result<Response, ApiError> {
    auth(&s, &jar, &headers, tid).await?;
    let whs = WebhookStore::list_by_tenant(&s.db, tid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = whs.iter().map(|w| serde_json::json!({"id":w.id,"endpoint_url":w.endpoint_url,"events":w.events,"is_active":w.is_active})).collect();
    Ok(Json(items).into_response())
}

pub async fn get_webhook(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((tid, wid)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    auth(&s, &jar, &headers, tid).await?;
    let w = webhook_in_tenant(&s, tid, wid).await?;
    Ok(Json(serde_json::json!({"id":w.id,"endpoint_url":w.endpoint_url,"events":w.events,"is_active":w.is_active})).into_response())
}

#[derive(Deserialize)]
pub struct PatchWebhookReq {
    pub endpoint_url: Option<String>,
    pub events: Option<String>,
    pub is_active: Option<bool>,
}

pub async fn patch_webhook(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((tid, wid)): Path<(Uuid, Uuid)>,
    Json(b): Json<PatchWebhookReq>,
) -> Result<Response, ApiError> {
    auth(&s, &jar, &headers, tid).await?;
    if let Some(ref new_url) = b.endpoint_url {
        validate_webhook_url(new_url, allow_insecure_webhooks())
            .map_err(|e| ApiError::bad_request("INVALID_ENDPOINT", &e))?;
    }
    let existing = webhook_in_tenant(&s, tid, wid).await?;
    WebhookStore::update(
        &s.db,
        wid,
        b.endpoint_url.as_deref().unwrap_or(&existing.endpoint_url),
        b.events.as_deref().unwrap_or(&existing.events),
        b.is_active.unwrap_or(existing.is_active),
    )
    .await
    .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn delete_webhook(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((tid, wid)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    auth(&s, &jar, &headers, tid).await?;
    // パスの tid と wid は独立に来るので、組であることを先に確かめる。
    webhook_in_tenant(&s, tid, wid).await?;
    WebhookStore::deactivate(&s.db, wid)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

pub async fn webhook_deliveries(
    State(s): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Path((tid, wid)): Path<(Uuid, Uuid)>,
) -> Result<Response, ApiError> {
    auth(&s, &jar, &headers, tid).await?;
    webhook_in_tenant(&s, tid, wid).await?;
    let dels = WebhookDeliveryStore::list_by_webhook(&s.db, wid, 50)
        .await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let items: Vec<serde_json::Value> = dels.iter().map(|d| serde_json::json!({"id":d.id,"event_type":d.event_type,"status":d.status,"status_code":d.status_code,"created_at":d.created_at.to_rfc3339()})).collect();
    Ok(Json(items).into_response())
}
