//! Axum Router — 100% compatible with Java volta-auth-proxy routes.

use axum::routing::{delete, get, patch, post, put};
use axum::Router;

use crate::handlers;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // Auth (ForwardAuth + session)
        .route("/auth/verify", get(handlers::auth::verify))
        .route("/auth/logout", get(handlers::auth::logout_get))
        .route("/auth/logout", post(handlers::auth::logout_post))
        .route("/auth/refresh", post(handlers::auth::refresh))
        .route("/auth/switch-tenant", post(handlers::auth::switch_tenant))

        // SAML
        .route("/auth/saml/login", get(handlers::saml::saml_login))
        .route("/auth/saml/callback", post(handlers::saml::saml_callback))

        // OIDC
        .route("/login", get(handlers::oidc::login))
        .route("/callback", get(handlers::oidc::callback))
        .route("/auth/callback/complete", post(handlers::oidc::callback_complete))

        // Sessions
        .route("/api/me/sessions", get(handlers::session::list_sessions))
        .route("/api/me/sessions", delete(handlers::session::revoke_all_sessions))
        .route("/api/me/sessions/{id}", delete(handlers::session::revoke_session))

        // User profile
        .route("/api/v1/users/me", get(handlers::user::me))
        .route("/api/v1/users/me/tenants", get(handlers::user::me_tenants))

        // MFA
        .route("/api/v1/users/{userId}/mfa/totp/setup", post(handlers::mfa::totp_setup))
        .route("/api/v1/users/{userId}/mfa/totp/verify", post(handlers::mfa::totp_verify_setup))
        .route("/api/v1/users/{userId}/mfa/totp", delete(handlers::mfa::totp_disable))
        .route("/api/v1/users/me/mfa", get(handlers::mfa::mfa_status))
        .route("/api/v1/users/{userId}/mfa/recovery-codes/regenerate", post(handlers::mfa::regenerate_recovery_codes))
        .route("/auth/mfa/verify", post(handlers::mfa::mfa_verify_login))

        // Magic Link
        .route("/auth/magic-link/send", post(handlers::magic_link::send))
        .route("/auth/magic-link/verify", get(handlers::magic_link::verify))

        // Signing Keys (admin)
        .route("/api/v1/admin/keys", get(handlers::signing_key::list_keys))
        .route("/api/v1/admin/keys/rotate", post(handlers::signing_key::rotate_key))
        .route("/api/v1/admin/keys/{kid}/revoke", post(handlers::signing_key::revoke_key))

        // Tenant
        .route("/api/v1/tenants", post(handlers::manage::create_tenant))
        .route("/api/v1/tenants/{tenantId}", get(handlers::manage::get_tenant))
        .route("/api/v1/tenants/{tenantId}", patch(handlers::manage::patch_tenant))

        // Member
        .route("/api/v1/tenants/{tenantId}/members", get(handlers::manage::list_members))
        .route("/api/v1/tenants/{tenantId}/members/{memberId}", patch(handlers::manage::patch_member))
        .route("/api/v1/tenants/{tenantId}/members/{memberId}", delete(handlers::manage::delete_member))

        // Invitation
        .route("/api/v1/tenants/{tenantId}/invitations", post(handlers::manage::create_invitation))
        .route("/api/v1/tenants/{tenantId}/invitations", get(handlers::manage::list_invitations))
        .route("/api/v1/tenants/{tenantId}/invitations/{invitationId}", delete(handlers::manage::cancel_invitation))
        .route("/invite/{code}/accept", post(handlers::manage::accept_invite))

        // IdP Config
        .route("/api/v1/tenants/{tenantId}/idp-configs", get(handlers::manage::list_idp_configs))
        .route("/api/v1/tenants/{tenantId}/idp-configs", post(handlers::manage::upsert_idp_config))

        // M2M Client
        .route("/api/v1/tenants/{tenantId}/m2m-clients", get(handlers::manage::list_m2m_clients))
        .route("/api/v1/tenants/{tenantId}/m2m-clients", post(handlers::manage::create_m2m_client))

        // OAuth2 Token (M2M)
        .route("/oauth/token", post(handlers::manage::oauth_token))

        // Passkey
        .route("/api/v1/users/{userId}/passkeys", get(handlers::manage::list_passkeys))
        .route("/api/v1/users/{userId}/passkeys/{passkeyId}", delete(handlers::manage::delete_passkey))

        // User management
        .route("/api/v1/users/{userId}", patch(handlers::manage::patch_user))
        .route("/api/v1/users/me", delete(handlers::manage::delete_user))

        // Webhooks
        .route("/api/v1/tenants/{tenantId}/webhooks", post(handlers::webhook::create_webhook))
        .route("/api/v1/tenants/{tenantId}/webhooks", get(handlers::webhook::list_webhooks))
        .route("/api/v1/tenants/{tenantId}/webhooks/{webhookId}", get(handlers::webhook::get_webhook))
        .route("/api/v1/tenants/{tenantId}/webhooks/{webhookId}", patch(handlers::webhook::patch_webhook))
        .route("/api/v1/tenants/{tenantId}/webhooks/{webhookId}", delete(handlers::webhook::delete_webhook))
        .route("/api/v1/tenants/{tenantId}/webhooks/{webhookId}/deliveries", get(handlers::webhook::webhook_deliveries))

        // Audit
        .route("/api/v1/admin/audit", get(handlers::admin::list_audit))

        // Devices
        .route("/api/v1/users/me/devices", get(handlers::admin::list_devices))
        .route("/api/v1/users/me/devices/{deviceId}", delete(handlers::admin::delete_device))
        .route("/api/v1/users/me/devices", delete(handlers::admin::delete_all_devices))

        // Billing
        .route("/api/v1/tenants/{tenantId}/billing", get(handlers::admin::get_billing))
        .route("/api/v1/tenants/{tenantId}/billing/subscription", post(handlers::admin::upsert_subscription))

        // Policy
        .route("/api/v1/tenants/{tenantId}/policies", get(handlers::admin::list_policies))
        .route("/api/v1/tenants/{tenantId}/policies", post(handlers::admin::create_policy))
        .route("/api/v1/tenants/{tenantId}/policies/evaluate", post(handlers::admin::evaluate_policy))

        // GDPR
        .route("/api/v1/users/me/data-export", post(handlers::admin::data_export))
        .route("/api/v1/users/{userId}/data", delete(handlers::admin::hard_delete_user))

        // Admin (system)
        .route("/api/v1/admin/tenants", get(handlers::admin::admin_list_tenants))
        .route("/api/v1/admin/users", get(handlers::admin::admin_list_users))
        .route("/api/v1/admin/outbox/flush", post(handlers::admin::outbox_flush))

        // SCIM 2.0
        .route("/scim/v2/Users", get(handlers::scim::list_users))
        .route("/scim/v2/Users", post(handlers::scim::create_user))
        .route("/scim/v2/Users/{id}", get(handlers::scim::get_user))
        .route("/scim/v2/Users/{id}", put(handlers::scim::replace_user))
        .route("/scim/v2/Users/{id}", patch(handlers::scim::patch_user))
        .route("/scim/v2/Users/{id}", delete(handlers::scim::delete_user))
        .route("/scim/v2/Groups", get(handlers::scim::list_groups))
        .route("/scim/v2/Groups", post(handlers::scim::create_group))

        // Passkey auth flow
        .route("/auth/passkey/start", post(handlers::passkey_flow::auth_start))
        .route("/auth/passkey/finish", post(handlers::passkey_flow::auth_finish))
        .route("/api/v1/users/{userId}/passkeys/register/start", post(handlers::passkey_flow::register_start))
        .route("/api/v1/users/{userId}/passkeys/register/finish", post(handlers::passkey_flow::register_finish))

        // Admin sessions
        .route("/admin/sessions", get(handlers::extra::admin_list_sessions))
        .route("/admin/sessions/{id}", delete(handlers::extra::admin_revoke_session))
        .route("/auth/sessions/{id}", delete(handlers::extra::revoke_session_by_id))
        .route("/auth/sessions/revoke-all", post(handlers::extra::revoke_all_sessions))

        // Transfer ownership
        .route("/api/v1/tenants/{tenantId}/transfer-ownership", post(handlers::extra::transfer_ownership))

        // Switch account + select tenant
        .route("/auth/switch-account", post(handlers::extra::switch_account))
        .route("/select-tenant", get(handlers::extra::select_tenant))

        // User export (admin)
        .route("/api/v1/users/{userId}/export", post(handlers::extra::admin_export_user))

        // Admin HTML pages (stubs)
        .route("/admin/members", get(handlers::extra::admin_members_page))
        .route("/admin/invitations", get(handlers::extra::admin_invitations_page))
        .route("/admin/webhooks", get(handlers::extra::admin_webhooks_page))
        .route("/admin/idp", get(handlers::extra::admin_idp_page))
        .route("/admin/tenants", get(handlers::extra::admin_tenants_page))
        .route("/admin/users", get(handlers::extra::admin_users_page))
        .route("/admin/audit", get(handlers::extra::admin_audit_page))

        // Settings pages (stubs)
        .route("/settings/security", get(handlers::extra::admin_members_page))
        .route("/settings/sessions", get(handlers::extra::admin_sessions_page))

        // Health + JWKS
        .route("/healthz", get(handlers::health::healthz))
        .route("/.well-known/jwks.json", get(handlers::health::jwks))

        .with_state(state)
}
