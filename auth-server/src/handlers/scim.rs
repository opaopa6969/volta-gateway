//! SCIM 2.0 handlers (RFC 7644) — /scim/v2/Users, /scim/v2/Groups.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;
use volta_auth_core::store::UserStore;

// SCIM response wrapper
fn scim_list(resources: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resources.len(),
        "Resources": resources,
    })
}

fn scim_user(id: Uuid, email: &str, name: Option<&str>, active: bool) -> serde_json::Value {
    serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": id.to_string(),
        "userName": email,
        "displayName": name.unwrap_or(""),
        "active": active,
        "emails": [{"value": email, "primary": true}],
    })
}

/// GET /scim/v2/Users
pub async fn list_users(State(s): State<AppState>) -> Result<Response, ApiError> {
    // Simplified — real impl would filter by tenant from Bearer token
    Ok(Json(scim_list(vec![])).into_response())
}

#[derive(Deserialize)]
pub struct ScimCreateUser {
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

/// POST /scim/v2/Users
pub async fn create_user(State(s): State<AppState>, Json(b): Json<ScimCreateUser>) -> Result<Response, ApiError> {
    let user = UserStore::upsert(&s.db, volta_auth_core::record::UserRecord {
        id: Uuid::new_v4(),
        email: b.user_name.clone(),
        display_name: b.display_name.clone(),
        google_sub: None,
        created_at: chrono::Utc::now(),
        is_active: true,
        locale: None,
        deleted_at: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    let mut resp = Json(scim_user(user.id, &user.email, user.display_name.as_deref(), user.is_active)).into_response();
    *resp.status_mut() = StatusCode::CREATED;
    Ok(resp)
}

/// GET /scim/v2/Users/{id}
pub async fn get_user(State(s): State<AppState>, Path(id): Path<Uuid>) -> Result<Response, ApiError> {
    let user = UserStore::find_by_id(&s.db, id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "user not found"))?;
    Ok(Json(scim_user(user.id, &user.email, user.display_name.as_deref(), user.is_active)).into_response())
}

/// PUT /scim/v2/Users/{id}
pub async fn replace_user(State(s): State<AppState>, Path(id): Path<Uuid>, Json(b): Json<ScimCreateUser>) -> Result<Response, ApiError> {
    UserStore::update_display_name(&s.db, id, b.display_name.as_deref().unwrap_or("")).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    let user = UserStore::find_by_id(&s.db, id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "user not found"))?;
    Ok(Json(scim_user(user.id, &user.email, user.display_name.as_deref(), user.is_active)).into_response())
}

/// PATCH /scim/v2/Users/{id}
pub async fn patch_user(State(s): State<AppState>, Path(id): Path<Uuid>, Json(b): Json<serde_json::Value>) -> Result<Response, ApiError> {
    // Simplified PATCH — extract displayName from Operations
    if let Some(ops) = b.get("Operations").and_then(|v| v.as_array()) {
        for op in ops {
            if op.get("path").and_then(|v| v.as_str()) == Some("displayName") {
                if let Some(val) = op.get("value").and_then(|v| v.as_str()) {
                    UserStore::update_display_name(&s.db, id, val).await
                        .map_err(|e| ApiError::internal(&e.to_string()))?;
                }
            }
        }
    }
    let user = UserStore::find_by_id(&s.db, id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("NOT_FOUND", "user not found"))?;
    Ok(Json(scim_user(user.id, &user.email, user.display_name.as_deref(), user.is_active)).into_response())
}

/// DELETE /scim/v2/Users/{id}
pub async fn delete_user(State(s): State<AppState>, Path(id): Path<Uuid>) -> Result<Response, ApiError> {
    UserStore::soft_delete(&s.db, id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// GET /scim/v2/Groups
pub async fn list_groups(State(_s): State<AppState>) -> Response {
    Json(scim_list(vec![])).into_response()
}

/// POST /scim/v2/Groups
pub async fn create_group(State(_s): State<AppState>, Json(_b): Json<serde_json::Value>) -> Response {
    // Groups map to tenants — simplified stub
    let mut resp = Json(serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": Uuid::new_v4().to_string(),
        "displayName": "group",
        "members": [],
    })).into_response();
    *resp.status_mut() = StatusCode::CREATED;
    resp
}
