//! Axum Router — 100% compatible with Java volta-auth-proxy routes.

use std::time::Duration;

use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, patch, post, put};
use axum::Router;

use crate::handlers;
use crate::rate_limit::{limit_by_ip, RateLimiter};
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    // #7, #10: per-endpoint rate limiters, keyed by client IP.
    // (Java: OIDC 10/min, MFA verify 5/min, passkey 5/min, invite 20/min.)
    let rl_oidc = RateLimiter::new("oidc", 10, Duration::from_secs(60));
    let rl_mfa = RateLimiter::new("mfa", 5, Duration::from_secs(60));
    let rl_passkey = RateLimiter::new("passkey", 5, Duration::from_secs(60));
    let rl_invite = RateLimiter::new("invite", 20, Duration::from_secs(60));
    let rl_magic = RateLimiter::new("magic-link", 5, Duration::from_secs(60));

    // Rate-limited route groups (mounted then merged into the main router below).
    let oidc_routes = Router::new()
        .route("/login", get(handlers::oidc::login))
        .route("/callback", get(handlers::oidc::callback))
        .route("/auth/callback/complete", post(handlers::oidc::callback_complete))
        .route_layer(from_fn_with_state(rl_oidc, limit_by_ip));

    let mfa_routes = Router::new()
        .route("/auth/mfa/verify", post(handlers::mfa::mfa_verify_login))
        .route_layer(from_fn_with_state(rl_mfa, limit_by_ip));

    let passkey_routes = Router::new()
        .route("/auth/passkey/start", post(handlers::passkey_flow::auth_start))
        .route("/auth/passkey/finish", post(handlers::passkey_flow::auth_finish))
        .route_layer(from_fn_with_state(rl_passkey, limit_by_ip));

    let invite_routes = Router::new()
        .route("/invite/{code}/accept", post(handlers::manage::accept_invite))
        .route_layer(from_fn_with_state(rl_invite, limit_by_ip));

    let magic_routes = Router::new()
        .route("/auth/magic-link/send", post(handlers::magic_link::send))
        .route("/auth/magic-link/verify", get(handlers::magic_link::verify))
        .route_layer(from_fn_with_state(rl_magic, limit_by_ip));

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

        // OIDC — moved into `oidc_routes` sub-router (rate-limited via route_layer)

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
        // GET /mfa/challenge — TOTP input page (AUTH-010)
        .route("/mfa/challenge", get(handlers::mfa::mfa_challenge))
        // /auth/mfa/verify — moved into `mfa_routes` sub-router (rate-limited)

        // Magic Link — moved into `magic_routes` sub-router (rate-limited)

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
        // /invite/{code}/accept — moved into `invite_routes` sub-router (rate-limited)

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
        // P2.1: new paginated sessions endpoint (matches Java `f31a2f2`)
        .route("/api/v1/admin/sessions", get(handlers::extra::admin_list_sessions))
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

        // Passkey auth flow — /auth/passkey/* moved into `passkey_routes` (rate-limited)
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

        // Viz (P1.2 SSE + P2.2 tramli-viz integration)
        .route("/viz/auth/stream", get(handlers::viz::auth_stream))
        .route("/viz/flows", get(handlers::viz::list_flows))
        .route("/api/v1/admin/flows/{flowId}/transitions", get(handlers::viz::flow_transitions))

        // Health + JWKS
        .route("/healthz", get(handlers::health::healthz))
        .route("/.well-known/jwks.json", get(handlers::health::jwks))

        .merge(oidc_routes)
        .merge(mfa_routes)
        .merge(passkey_routes)
        .merge(invite_routes)
        .merge(magic_routes)
        .with_state(state)
}
