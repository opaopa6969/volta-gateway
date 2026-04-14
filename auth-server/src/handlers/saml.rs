//! SAML SSO handlers — /auth/saml/login + /auth/saml/callback.
//! Direct port from Java AuthRouter SAML routes.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::error::{no_cache_headers, ApiError};
use crate::helpers::{is_json_accept, set_session_cookie};
use crate::saml;
use crate::state::AppState;
use volta_auth_core::store::*;

#[derive(Deserialize)]
pub struct SamlLoginQuery {
    pub tenant_id: Option<String>,
    pub return_to: Option<String>,
}

/// GET /auth/saml/login — redirect to SAML IdP.
pub async fn saml_login(
    State(s): State<AppState>,
    Query(q): Query<SamlLoginQuery>,
) -> Result<Response, ApiError> {
    let tenant_id_str = q.tenant_id
        .ok_or_else(|| ApiError::bad_request("BAD_REQUEST", "tenant_id is required"))?;
    let tenant_id: Uuid = tenant_id_str.parse()
        .map_err(|_| ApiError::bad_request("BAD_REQUEST", "invalid tenant_id"))?;

    // Load SAML IdP config
    let idp = IdpConfigStore::find(&s.db, tenant_id, "SAML").await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("IDP_NOT_FOUND", "SAML IdP 設定が見つかりません。"))?;

    let entry = idp.metadata_url.as_deref()
        .or(idp.issuer.as_deref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ApiError::bad_request("IDP_INVALID", "SAML エントリーポイントが未設定です。"))?;

    let request_id = format!("_{}", Uuid::new_v4().to_string().replace('-', "")[..16].to_string());
    let relay = saml::encode_relay_state(&saml::RelayState {
        tenant_id: Some(tenant_id_str),
        return_to: q.return_to,
        request_id: Some(request_id),
    });

    let separator = if entry.contains('?') { "&" } else { "?" };
    let redirect_url = format!("{}{}RelayState={}", entry, separator, urlencoding::encode(&relay));

    let mut resp = Redirect::to(&redirect_url).into_response();
    no_cache_headers(&mut resp);
    Ok(resp)
}

/// POST /auth/saml/callback — receive SAML assertion from IdP.
pub async fn saml_callback(
    State(s): State<AppState>,
    headers: HeaderMap,
    form: axum::extract::Form<SamlCallbackForm>,
) -> Result<Response, ApiError> {
    let relay = saml::decode_relay_state(form.relay_state.as_deref());

    let tenant_id_str = relay.tenant_id
        .ok_or_else(|| ApiError::bad_request("BAD_REQUEST", "tenant_id is required in RelayState"))?;
    let tenant_id: Uuid = tenant_id_str.parse()
        .map_err(|_| ApiError::bad_request("BAD_REQUEST", "invalid tenant_id"))?;

    // Load SAML IdP config
    let idp = IdpConfigStore::find(&s.db, tenant_id, "SAML").await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("IDP_NOT_FOUND", "SAML IdP 設定が見つかりません。"))?;

    let saml_response = form.saml_response.as_deref().unwrap_or("");

    let acs_url = format!("{}/auth/saml/callback", s.base_url);
    // #8: SAML_SKIP_SIGNATURE only takes effect on localhost requests. Any production
    // deployment receives traffic through a gateway whose forwarded IP is non-loopback,
    // so signature verification can never be accidentally disabled by env.
    let skip_sig = std::env::var("SAML_SKIP_SIGNATURE").unwrap_or_default() == "true"
        && crate::security::is_localhost_request(&headers);

    let identity = saml::parse_identity(
        saml_response,
        idp.issuer.as_deref(),
        idp.x509_cert.as_deref(),
        idp.client_id.as_deref(), // audience = SP entity ID
        skip_sig,
        Some(&acs_url),
        relay.request_id.as_deref(),
    )?;

    // Upsert user
    let provider_sub = format!("saml:{}", sha256_hex(&format!(
        "{}|{}", identity.issuer, identity.email.to_lowercase()
    )));
    let user = UserStore::upsert(&s.db, volta_auth_core::record::UserRecord {
        id: Uuid::new_v4(),
        email: identity.email.clone(),
        display_name: Some(identity.display_name.clone()),
        google_sub: Some(provider_sub),
        created_at: chrono::Utc::now(),
        is_active: true,
        locale: None,
        deleted_at: None,
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    // Verify tenant membership
    let tenant = TenantStore::find_by_id(&s.db, tenant_id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::bad_request("TENANT_NOT_FOUND", "テナントが見つかりません。"))?;

    let membership = MembershipStore::find(&s.db, user.id, tenant.id).await
        .map_err(|e| ApiError::internal(&e.to_string()))?
        .ok_or_else(|| ApiError::forbidden("TENANT_ACCESS_DENIED", "Tenant membership not found"))?;

    if !membership.is_active {
        return Err(ApiError::forbidden("TENANT_ACCESS_DENIED", "Tenant membership not active"));
    }

    // Create session
    let session_id = Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    SessionStore::create(&s.db, volta_auth_core::record::SessionRecord {
        session_id: session_id.clone(),
        user_id: user.id.to_string(),
        tenant_id: tenant.id.to_string(),
        return_to: relay.return_to.clone(),
        created_at: now,
        last_active_at: now,
        expires_at: now + s.session_ttl_secs,
        invalidated_at: None,
        mfa_verified_at: None,
        ip_address: None,
        user_agent: None,
        csrf_token: None,
        email: Some(identity.email),
        tenant_slug: Some(tenant.slug),
        roles: vec![membership.role],
        display_name: Some(identity.display_name),
    }).await.map_err(|e| ApiError::internal(&e.to_string()))?;

    let redirect_to = relay.return_to
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "/select-tenant".to_string());

    if is_json_accept(&headers) {
        let mut resp = Json(serde_json::json!({"redirect_to": redirect_to})).into_response();
        set_session_cookie(&mut resp, &session_id, &s);
        no_cache_headers(&mut resp);
        Ok(resp)
    } else {
        let mut resp = Redirect::to(&redirect_to).into_response();
        set_session_cookie(&mut resp, &session_id, &s);
        no_cache_headers(&mut resp);
        Ok(resp)
    }
}

#[derive(Deserialize)]
pub struct SamlCallbackForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: Option<String>,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

fn sha256_hex(input: &str) -> String {
    use sha2::{Sha256, Digest};
    hex::encode(Sha256::digest(input.as_bytes()))
}
