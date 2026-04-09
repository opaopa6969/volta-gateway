//! AuthService — async orchestrator that drives tramli SM flows
//! with real IdP, Store, and JWT operations.
//!
//! tramli processors are sync; this service performs async I/O first,
//! then feeds results into the SM context and drives transitions.

use std::any::TypeId;
use std::sync::Arc;

use tramli::{CloneAny, FlowEngine, InMemoryFlowStore};

use crate::error::AuthError;
use crate::idp::{IdpClient, IdpUserInfo, TokenResponse};
use crate::jwt::{JwtIssuer, VoltaClaims};
use crate::record::{SessionRecord, UserRecord};
use crate::store::{SessionStore, UserStore, TenantStore, MembershipStore, InvitationStore};
use crate::totp;
use crate::flow::oidc::{self, OidcInitData, OidcUserData};
use crate::flow::mfa::{self, MfaChallenge, MfaCode};
use crate::token::{self, TokenRequest, TokenValidation};

// ─── Result types ──────────────────────────────────────────

/// Result of a successful OIDC flow.
#[derive(Debug, Clone)]
pub struct OidcStartResult {
    pub flow_id: String,
    pub authorization_url: String,
}

/// Result of a successful OIDC callback.
#[derive(Debug, Clone)]
pub struct OidcCallbackResult {
    pub session_jwt: String,
    pub user: OidcUserData,
    pub session_id: String,
    pub mfa_required: bool,
}

/// Result of a successful token refresh.
#[derive(Debug, Clone)]
pub struct TokenRefreshResult {
    pub jwt: String,
    pub refresh_token: String,
    pub expires_at: u64,
}

// ─── AuthService ───────────────────────────────────────────

pub struct AuthService {
    pub idp: IdpClient,
    pub user_store: Arc<dyn UserStore>,
    pub tenant_store: Arc<dyn TenantStore>,
    pub membership_store: Arc<dyn MembershipStore>,
    pub invitation_store: Arc<dyn InvitationStore>,
    pub session_store: Arc<dyn SessionStore>,
    pub jwt_issuer: JwtIssuer,
}

impl AuthService {
    // ─── OIDC ──────────────────────────────────────────

    /// Start OIDC flow: build authorization URL and create SM flow.
    pub fn oidc_start(&self, init: OidcInitData) -> Result<OidcStartResult, AuthError> {
        let url = self.idp.authorization_url(&init.redirect_uri, &init.state, &init.nonce);

        let def = oidc::build_oidc_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<OidcInitData>(), Box::new(init)),
        ];
        let flow_id = engine.start_flow(def, "oidc", data)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(OidcStartResult { flow_id, authorization_url: url })
    }

    /// Handle OIDC callback: exchange code → userinfo → upsert user → create session.
    pub async fn oidc_callback(
        &self,
        code: &str,
        _state: &str,
        redirect_uri: &str,
    ) -> Result<OidcCallbackResult, AuthError> {
        // 1. Exchange code for tokens (async IdP call)
        let token_resp: TokenResponse = self.idp.exchange_code(code, redirect_uri).await
            .map_err(|e| AuthError::Internal(e))?;

        // 2. Fetch userinfo (async IdP call)
        let userinfo: IdpUserInfo = self.idp.userinfo(&token_resp.access_token).await
            .map_err(|e| AuthError::Internal(e))?;

        let email = userinfo.email.clone()
            .ok_or_else(|| AuthError::Internal("IdP did not return email".into()))?;

        // 3. Upsert user in DB
        let now = chrono::Utc::now();
        let user = self.user_store.upsert(UserRecord {
            id: uuid::Uuid::new_v4(),
            email: email.clone(),
            display_name: userinfo.name.clone(),
            google_sub: Some(userinfo.sub.clone()),
            created_at: now,
            is_active: true,
            locale: None,
            deleted_at: None,
        }).await?;

        // 4. Resolve tenant + roles
        let tenants = self.tenant_store.find_by_user(user.id).await?;
        let (tenant_id, roles) = if let Some(t) = tenants.first() {
            let membership = self.membership_store.find(user.id, t.id).await?;
            let role = membership.map(|m| m.role).unwrap_or_else(|| "MEMBER".into());
            (t.id.to_string(), vec![role])
        } else {
            // First login — create personal tenant
            let slug = email.split('@').next().unwrap_or("user").to_string();
            let display = user.display_name.clone().unwrap_or_else(|| email.clone());
            let tenant = self.tenant_store.create_personal(user.id, &display, &slug).await?;
            (tenant.id.to_string(), vec!["OWNER".into()])
        };

        let is_new_user = tenants.is_empty();

        let oidc_user = OidcUserData {
            user_id: user.id.to_string(),
            email: email.clone(),
            display_name: userinfo.name.unwrap_or_default(),
            tenant_id: tenant_id.clone(),
            roles: roles.clone(),
            is_new_user,
        };

        // 5. Create session
        let session_id = uuid::Uuid::new_v4().to_string();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = now_epoch + self.jwt_issuer.ttl_secs();

        self.session_store.create(SessionRecord {
            session_id: session_id.clone(),
            user_id: user.id.to_string(),
            tenant_id: tenant_id.clone(),
            return_to: None,
            created_at: now_epoch,
            last_active_at: now_epoch,
            expires_at,
            invalidated_at: None,
            mfa_verified_at: None,
            ip_address: None,
            user_agent: None,
            csrf_token: None,
            email: Some(email.clone()),
            tenant_slug: tenants.first().map(|t| t.slug.clone()),
            roles: roles.clone(),
            display_name: user.display_name.clone(),
        }).await?;

        // 6. Issue JWT
        let jwt = self.jwt_issuer.issue(&VoltaClaims {
            sub: user.id.to_string(),
            email: Some(email),
            tenant_id: Some(tenant_id),
            tenant_slug: tenants.first().map(|t| t.slug.clone()),
            roles: Some(roles.join(",")),
            name: user.display_name,
            app_id: None,
            iat: None, // set by issuer
            exp: None,
        }).map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(OidcCallbackResult {
            session_jwt: jwt,
            user: oidc_user,
            session_id,
            mfa_required: false, // TODO: risk check
        })
    }

    // ─── MFA ───────────────────────────────────────────

    /// Verify a TOTP code and mark session as MFA-verified.
    pub async fn mfa_verify(
        &self,
        session_id: &str,
        code: &str,
        secret: &[u8],
    ) -> Result<(), AuthError> {
        let valid = totp::verify_totp(secret, code, 30);

        if !valid {
            return Err(AuthError::PolicyDenied("invalid TOTP code".into()));
        }

        // Mark session MFA verified
        self.session_store.mark_mfa_verified(session_id).await?;

        // Drive MFA SM for audit trail
        let def = mfa::build_mfa_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let init_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<MfaChallenge>(), Box::new(MfaChallenge {
                session_id: session_id.into(),
                method: "totp".into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "mfa", init_data)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let resume: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<MfaCode>(), Box::new(MfaCode {
                code: code.into(),
                valid: true,
            })),
        ];
        engine.resume_and_execute(&flow_id, resume)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(())
    }

    // ─── Token Refresh ─────────────────────────────────

    /// Refresh a session token: validate session → issue new JWT.
    pub async fn token_refresh(
        &self,
        session_id: &str,
        refresh_token: &str,
        client_ip: &str,
    ) -> Result<TokenRefreshResult, AuthError> {
        // 1. Check session is valid
        let session = self.session_store.find(session_id).await?
            .ok_or(AuthError::SessionNotFound)?;

        // 2. Touch session (extend expiry)
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let new_expires = now_epoch + self.jwt_issuer.ttl_secs();
        self.session_store.touch(session_id, new_expires).await?;

        // 3. Issue new JWT
        let jwt = self.jwt_issuer.issue(&VoltaClaims {
            sub: session.user_id.clone(),
            email: session.email.clone(),
            tenant_id: Some(session.tenant_id.clone()),
            tenant_slug: session.tenant_slug.clone(),
            roles: if session.roles.is_empty() { None } else { Some(session.roles.join(",")) },
            name: session.display_name.clone(),
            app_id: None,
            iat: None,
            exp: None,
        }).map_err(|e| AuthError::Internal(e.to_string()))?;

        // 4. Drive token SM for audit
        let def = token::build_token_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<TokenRequest>(), Box::new(TokenRequest {
                refresh_token: refresh_token.into(),
                session_id: session_id.into(),
                client_ip: client_ip.into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "token", data)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        // Resume with validation
        let validation: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<TokenValidation>(), Box::new(TokenValidation {
                user_id: session.user_id,
                tenant_id: session.tenant_id,
                roles: session.roles,
                valid: true,
            })),
        ];
        engine.resume_and_execute(&flow_id, validation)
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(TokenRefreshResult {
            jwt,
            refresh_token: uuid::Uuid::new_v4().to_string(),
            expires_at: new_expires,
        })
    }

    // ─── Invite ────────────────────────────────────────

    /// Accept an invitation: validate → create membership → return result.
    pub async fn invite_accept(
        &self,
        code: &str,
        user_id: uuid::Uuid,
    ) -> Result<(), AuthError> {
        // InvitationStore.accept() handles: find invitation, check usability,
        // increment used_count, record usage, create membership — all in a tx.
        self.invitation_store.accept(code, user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::JwtVerifier;

    #[test]
    fn jwt_issue_verify_roundtrip() {
        let secret = b"test-secret-at-least-32-bytes!!!";
        let issuer = JwtIssuer::new_hs256(secret, 3600);
        let verifier = JwtVerifier::new_hs256(secret);

        let claims = VoltaClaims {
            sub: "user-123".into(),
            email: Some("test@test.com".into()),
            tenant_id: Some("tenant-1".into()),
            tenant_slug: Some("acme".into()),
            roles: Some("MEMBER".into()),
            name: Some("Test User".into()),
            app_id: None,
            iat: None,
            exp: None,
        };

        let token = issuer.issue(&claims).unwrap();
        let verified = verifier.verify(&token).unwrap();

        assert_eq!(verified.sub, "user-123");
        assert_eq!(verified.email.unwrap(), "test@test.com");
        assert_eq!(verified.tenant_id.unwrap(), "tenant-1");
        assert!(verified.exp.unwrap() > verified.iat.unwrap());
    }
}
