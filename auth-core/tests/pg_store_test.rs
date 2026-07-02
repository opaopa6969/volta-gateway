//! Integration tests for PgStore — requires Docker and `postgres` feature.
//! Run: cargo test -p volta-auth-core --features postgres -- --ignored

#![cfg(feature = "postgres")]

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use volta_auth_core::record::*;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::*;

async fn setup_pool() -> (PgPool, testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>) {
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);

    let pool = PgPool::connect(&url).await.unwrap();

    let migrations = [
        include_str!("../migrations/001_create_users.sql"),
        include_str!("../migrations/002_create_tenants.sql"),
        include_str!("../migrations/003_create_memberships.sql"),
        include_str!("../migrations/004_create_invitations.sql"),
        include_str!("../migrations/005_create_invitation_usages.sql"),
        include_str!("../migrations/006_create_auth_flows.sql"),
        include_str!("../migrations/007_create_auth_flow_transitions.sql"),
    ];
    for sql in &migrations {
        sqlx::raw_sql(sql).execute(&pool).await.unwrap();
    }

    (pool, container)
}

/// Helper: typed accessors to avoid UFCS everywhere.
fn users(s: &PgStore) -> &(dyn UserStore + '_) { s }
fn tenants(s: &PgStore) -> &(dyn TenantStore + '_) { s }
fn memberships(s: &PgStore) -> &(dyn MembershipStore + '_) { s }
fn invitations(s: &PgStore) -> &(dyn InvitationStore + '_) { s }
fn flows(s: &PgStore) -> &(dyn FlowPersistence + '_) { s }

async fn create_user(s: &PgStore, email: &str, gsub: &str) -> UserRecord {
    users(s).upsert(UserRecord {
        id: Uuid::new_v4(), email: email.into(),
        display_name: Some(email.split('@').next().unwrap().into()),
        google_sub: Some(gsub.into()),
        created_at: Utc::now(), is_active: true, locale: None, deleted_at: None,
    }).await.unwrap()
}

// ─── UserStore ─────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn user_upsert_and_find() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let created = create_user(&store, "alice@example.com", "google-alice").await;

    // Find by ID
    let found = users(&store).find_by_id(created.id).await.unwrap().unwrap();
    assert_eq!(found.email, "alice@example.com");

    // Find by email
    let found = users(&store).find_by_email("alice@example.com").await.unwrap().unwrap();
    assert_eq!(found.id, created.id);

    // Find by google_sub
    let found = users(&store).find_by_google_sub("google-alice").await.unwrap().unwrap();
    assert_eq!(found.id, created.id);

    // Update display name
    users(&store).update_display_name(created.id, "Alice Updated").await.unwrap();
    let found = users(&store).find_by_id(created.id).await.unwrap().unwrap();
    assert_eq!(found.display_name.as_deref(), Some("Alice Updated"));

    // Soft delete
    users(&store).soft_delete(created.id).await.unwrap();
    let found = users(&store).find_by_id(created.id).await.unwrap().unwrap();
    assert!(found.deleted_at.is_some());
}

#[tokio::test]
#[ignore]
async fn user_upsert_conflict_updates() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    create_user(&store, "bob@example.com", "google-bob").await;

    // Upsert same email with different display name
    let updated = users(&store).upsert(UserRecord {
        id: Uuid::new_v4(), email: "bob@example.com".into(),
        display_name: Some("Bob Updated".into()),
        google_sub: Some("google-bob".into()),
        created_at: Utc::now(), is_active: true, locale: None, deleted_at: None,
    }).await.unwrap();
    assert_eq!(updated.display_name.as_deref(), Some("Bob Updated"));
}

// ─── TenantStore ───────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn tenant_crud() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let user = create_user(&store, "owner@example.com", "google-owner").await;

    let tenant = tenants(&store).create(TenantRecord {
        id: Uuid::new_v4(), name: "Acme Corp".into(), slug: "acme".into(),
        email_domain: Some("acme.com".into()), auto_join: false,
        created_by: Some(user.id), created_at: Utc::now(),
        plan: Some("FREE".into()), max_members: Some(50),
        is_active: true, mfa_required: false, mfa_grace_until: None,
    }).await.unwrap();

    assert_eq!(tenant.slug, "acme");

    let found = tenants(&store).find_by_id(tenant.id).await.unwrap().unwrap();
    assert_eq!(found.name, "Acme Corp");

    let found = tenants(&store).find_by_slug("acme").await.unwrap().unwrap();
    assert_eq!(found.id, tenant.id);
}

#[tokio::test]
#[ignore]
async fn tenant_create_personal_with_membership() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let user = create_user(&store, "personal@example.com", "google-personal").await;

    let tenant = tenants(&store).create_personal(user.id, "Personal", "personal-user").await.unwrap();
    assert_eq!(tenant.plan.as_deref(), Some("FREE"));

    let found = tenants(&store).find_by_user(user.id).await.unwrap();
    assert_eq!(found.len(), 1);

    let m = memberships(&store).find(user.id, tenant.id).await.unwrap().unwrap();
    assert_eq!(m.role, "OWNER");
}

// ─── MembershipStore ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn membership_crud() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let owner = create_user(&store, "mem-owner@example.com", "google-mem-owner").await;
    let member = create_user(&store, "mem-member@example.com", "google-mem-member").await;
    let tenant = tenants(&store).create_personal(owner.id, "Team", "mem-team").await.unwrap();

    memberships(&store).create(MembershipRecord {
        id: Uuid::new_v4(), user_id: member.id, tenant_id: tenant.id,
        role: "MEMBER".into(), joined_at: Utc::now(),
        invited_by: Some(owner.id), is_active: true,
    }).await.unwrap();

    let found = memberships(&store).find(member.id, tenant.id).await.unwrap().unwrap();
    assert_eq!(found.role, "MEMBER");

    let list = memberships(&store).list_by_tenant(tenant.id).await.unwrap();
    assert_eq!(list.len(), 2); // owner + member

    assert_eq!(memberships(&store).count_active_owners(tenant.id).await.unwrap(), 1);

    memberships(&store).update_role(found.id, "ADMIN").await.unwrap();
    let updated = memberships(&store).find(member.id, tenant.id).await.unwrap().unwrap();
    assert_eq!(updated.role, "ADMIN");

    memberships(&store).deactivate(found.id).await.unwrap();
    let list = memberships(&store).list_by_tenant(tenant.id).await.unwrap();
    assert_eq!(list.len(), 1); // only owner
}

// ─── InvitationStore ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn invitation_crud_and_accept() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let owner = create_user(&store, "inv-owner@example.com", "google-inv-owner").await;
    let invitee = create_user(&store, "invitee@example.com", "google-invitee").await;
    let tenant = tenants(&store).create_personal(owner.id, "Inv Team", "inv-team").await.unwrap();

    invitations(&store).create(InvitationRecord {
        id: Uuid::new_v4(), tenant_id: tenant.id, code: "inv-code-123".into(),
        email: Some("invitee@example.com".into()), role: "MEMBER".into(),
        max_uses: 1, used_count: 0, created_by: owner.id,
        created_at: Utc::now(), expires_at: Utc::now() + chrono::Duration::hours(24),
    }).await.unwrap();

    let found = invitations(&store).find_by_code("inv-code-123").await.unwrap().unwrap();
    assert!(found.is_usable_at(Utc::now()));

    let list = invitations(&store).list_by_tenant(tenant.id).await.unwrap();
    assert_eq!(list.len(), 1);

    // Accept
    invitations(&store).accept("inv-code-123", invitee.id).await.unwrap();

    let found = invitations(&store).find_by_code("inv-code-123").await.unwrap().unwrap();
    assert_eq!(found.used_count, 1);
    assert!(!found.is_usable_at(Utc::now()));

    let m = memberships(&store).find(invitee.id, tenant.id).await.unwrap().unwrap();
    assert_eq!(m.role, "MEMBER");
}

#[tokio::test]
#[ignore]
async fn invitation_cancel() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let owner = create_user(&store, "cancel-owner@example.com", "google-cancel-owner").await;
    let tenant = tenants(&store).create_personal(owner.id, "Cancel Team", "cancel-team").await.unwrap();

    let inv_id = Uuid::new_v4();
    invitations(&store).create(InvitationRecord {
        id: inv_id, tenant_id: tenant.id, code: "inv-cancel-123".into(),
        email: None, role: "MEMBER".into(), max_uses: 5, used_count: 0,
        created_by: owner.id, created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::hours(24),
    }).await.unwrap();

    invitations(&store).cancel(inv_id).await.unwrap();

    let found = invitations(&store).find_by_code("inv-cancel-123").await.unwrap().unwrap();
    assert!(!found.is_usable_at(Utc::now()));
}

// ─── FlowPersistence ──────────────────────────────────────

#[tokio::test]
#[ignore]
async fn flow_lifecycle() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let flow_id = Uuid::new_v4();
    let now = Utc::now();

    // Create flow
    flows(&store).create(FlowRecord {
        id: flow_id,
        session_id: "session-1".into(),
        flow_type: "oidc".into(),
        current_state: "Init".into(),
        guard_failure_count: 0,
        version: 0,
        created_at: now,
        updated_at: now,
        expires_at: now + chrono::Duration::minutes(10),
        completed_at: None,
        exit_state: None,
        summary: None,
    }).await.unwrap();

    // Find
    let found = flows(&store).find(flow_id).await.unwrap().unwrap();
    assert_eq!(found.flow_type, "oidc");
    assert_eq!(found.current_state, "Init");

    // Record transition
    flows(&store).record_transition(flow_id, Some("Init"), "Redirected", "auto:OidcInit", None).await.unwrap();

    // Update state (optimistic lock: version 0 → 1)
    flows(&store).update_state(flow_id, "Redirected", 1).await.unwrap();
    let found = flows(&store).find(flow_id).await.unwrap().unwrap();
    assert_eq!(found.current_state, "Redirected");
    assert_eq!(found.version, 1);

    // Optimistic lock conflict
    let err = flows(&store).update_state(flow_id, "X", 1).await;
    assert!(err.is_err());

    // Find active by session
    let active = flows(&store).find_active_by_session("session-1").await.unwrap();
    assert_eq!(active.len(), 1);

    // Complete
    let summary = serde_json::json!({"user_id": "u-1", "outcome": "success"});
    flows(&store).complete(flow_id, "Complete", Some(summary)).await.unwrap();
    let found = flows(&store).find(flow_id).await.unwrap().unwrap();
    assert_eq!(found.exit_state.as_deref(), Some("Complete"));
    assert!(found.completed_at.is_some());

    // Active flows should be empty now
    let active = flows(&store).find_active_by_session("session-1").await.unwrap();
    assert_eq!(active.len(), 0);
}

#[tokio::test]
#[ignore]
async fn flow_cleanup_expired() {
    let (pool, _c) = setup_pool().await;
    let store = PgStore::new(pool);

    let now = Utc::now();

    // Create an already-expired flow
    flows(&store).create(FlowRecord {
        id: Uuid::new_v4(),
        session_id: "expired-session".into(),
        flow_type: "oidc".into(),
        current_state: "Init".into(),
        guard_failure_count: 0,
        version: 0,
        created_at: now - chrono::Duration::hours(1),
        updated_at: now - chrono::Duration::hours(1),
        expires_at: now - chrono::Duration::minutes(1), // already expired
        completed_at: None,
        exit_state: None,
        summary: None,
    }).await.unwrap();

    let cleaned = flows(&store).cleanup_expired().await.unwrap();
    assert_eq!(cleaned, 1);
}

// ─── DeviceGrantStore (RFC 8628) ───────────────────────────

fn device_grants(s: &PgStore) -> &(dyn DeviceGrantStore + '_) { s }

async fn setup_device_pool() -> (PgPool, testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>) {
    let (pool, c) = setup_pool().await;
    // device_authorization_grants has no FKs — apply just its migration.
    sqlx::raw_sql(include_str!("../migrations/028_create_device_authorization_grants.sql"))
        .execute(&pool).await.unwrap();
    (pool, c)
}

fn new_grant(device_code: &str, user_code: &str, interval: i32, ttl_secs: i64) -> DeviceGrantRecord {
    DeviceGrantRecord {
        id: Uuid::new_v4(),
        device_code_hash: volta_auth_core::crypto::sha256_hex(device_code),
        user_code: user_code.into(),
        client_id: "cli-app".into(),
        scope: Some("openid profile".into()),
        status: "pending".into(),
        user_id: None,
        tenant_id: None,
        interval_secs: interval,
        last_polled_at: None,
        created_at: Utc::now(),
        expires_at: Utc::now() + chrono::Duration::seconds(ttl_secs),
    }
}

#[tokio::test]
#[ignore]
async fn device_grant_full_lifecycle() {
    let (pool, _c) = setup_device_pool().await;
    let store = PgStore::new(pool);
    let hash = volta_auth_core::crypto::sha256_hex("device-code-1");
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // interval 0 → no slow_down interference for this test.
    device_grants(&store).create(new_grant("device-code-1", "WDJB-MJHT", 0, 600)).await.unwrap();

    // Visible to the approval page.
    let pending = device_grants(&store).find_pending_by_user_code("WDJB-MJHT").await.unwrap();
    assert!(pending.is_some());

    // Before approval the device just gets Pending.
    assert_eq!(device_grants(&store).poll(&hash).await.unwrap(), DevicePollOutcome::Pending);

    // User approves.
    let dec = device_grants(&store).decide("WDJB-MJHT", true, user_id, tenant_id).await.unwrap();
    assert!(matches!(dec, DeviceDecisionOutcome::Ok { .. }));

    // Now the device poll yields the identity.
    match device_grants(&store).poll(&hash).await.unwrap() {
        DevicePollOutcome::Approved { user_id: u, tenant_id: t, scope } => {
            assert_eq!(u, user_id);
            assert_eq!(t, tenant_id);
            assert_eq!(scope.as_deref(), Some("openid profile"));
        }
        other => panic!("expected Approved, got {other:?}"),
    }

    // No longer pending on the approval page.
    assert!(device_grants(&store).find_pending_by_user_code("WDJB-MJHT").await.unwrap().is_none());

    // Token issued → single-use consume → gone.
    device_grants(&store).consume(&hash).await.unwrap();
    assert_eq!(device_grants(&store).poll(&hash).await.unwrap(), DevicePollOutcome::NotFound);
}

#[tokio::test]
#[ignore]
async fn device_grant_deny_and_slow_down_and_expiry() {
    let (pool, _c) = setup_device_pool().await;
    let store = PgStore::new(pool);
    let uid = Uuid::new_v4();
    let tid = Uuid::new_v4();

    // Deny → access_denied.
    device_grants(&store).create(new_grant("dc-deny", "AAAA-BBBB", 0, 600)).await.unwrap();
    device_grants(&store).decide("AAAA-BBBB", false, uid, tid).await.unwrap();
    let h_deny = volta_auth_core::crypto::sha256_hex("dc-deny");
    assert_eq!(device_grants(&store).poll(&h_deny).await.unwrap(), DevicePollOutcome::Denied);

    // slow_down: interval 5, two quick polls → second is throttled.
    device_grants(&store).create(new_grant("dc-slow", "CCCC-DDDD", 5, 600)).await.unwrap();
    let h_slow = volta_auth_core::crypto::sha256_hex("dc-slow");
    assert_eq!(device_grants(&store).poll(&h_slow).await.unwrap(), DevicePollOutcome::Pending);
    assert_eq!(device_grants(&store).poll(&h_slow).await.unwrap(), DevicePollOutcome::SlowDown);

    // Expired grant → expired_token, and cleanup removes it.
    device_grants(&store).create(new_grant("dc-exp", "EEEE-FFFF", 0, -1)).await.unwrap();
    let h_exp = volta_auth_core::crypto::sha256_hex("dc-exp");
    assert_eq!(device_grants(&store).poll(&h_exp).await.unwrap(), DevicePollOutcome::Expired);
    assert_eq!(device_grants(&store).delete_expired().await.unwrap(), 1);
}

// ─── OAuth Provider stores (Phase 3b) ──────────────────────

async fn setup_oauth_pool() -> (PgPool, testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>) {
    let (pool, c) = setup_pool().await;
    sqlx::raw_sql(include_str!("../migrations/029_create_oauth_provider.sql"))
        .execute(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/031_oauth_client_logout_uris.sql"))
        .execute(&pool).await.unwrap();
    (pool, c)
}

fn oauth_client(s: &PgStore) -> &(dyn OAuthClientStore + '_) { s }
fn authz(s: &PgStore) -> &(dyn AuthzCodeStore + '_) { s }
fn refresh(s: &PgStore) -> &(dyn RefreshTokenStore + '_) { s }
fn consent(s: &PgStore) -> &(dyn OAuthConsentStore + '_) { s }

#[tokio::test]
#[ignore]
async fn oauth_client_and_consent() {
    let (pool, _c) = setup_oauth_pool().await;
    let store = PgStore::new(pool);
    oauth_client(&store).create_client(OAuthClientRecord {
        id: Uuid::new_v4(), client_id: "cli-1".into(), client_secret_hash: None,
        name: "RP".into(), redirect_uris: vec!["https://rp/cb".into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        scopes: vec!["openid".into(), "email".into()], is_confidential: false,
        backchannel_logout_uri: Some("https://rp/bclogout".into()), frontchannel_logout_uri: None,
        created_at: Utc::now(),
    }).await.unwrap();
    let c = oauth_client(&store).find_client("cli-1").await.unwrap().unwrap();
    assert!(c.allows_redirect("https://rp/cb") && !c.allows_redirect("https://evil/cb"));
    assert!(c.allows_grant("refresh_token"));
    assert_eq!(c.backchannel_logout_uri.as_deref(), Some("https://rp/bclogout"));

    let uid = Uuid::new_v4();
    assert!(!consent(&store).has_consent(uid, "cli-1", "openid email").await.unwrap());
    consent(&store).grant_consent(uid, "cli-1", "openid email profile").await.unwrap();
    // superset grant covers a subset request
    assert!(consent(&store).has_consent(uid, "cli-1", "openid email").await.unwrap());
    // but not an un-granted scope
    assert!(!consent(&store).has_consent(uid, "cli-1", "offline_access").await.unwrap());
}

#[tokio::test]
#[ignore]
async fn authz_code_is_single_use() {
    let (pool, _c) = setup_oauth_pool().await;
    let store = PgStore::new(pool);
    let hash = volta_auth_core::crypto::sha256_hex("thecode");
    authz(&store).save_code(AuthzCodeRecord {
        code_hash: hash.clone(), client_id: "cli-1".into(),
        user_id: Uuid::new_v4(), tenant_id: Uuid::new_v4(),
        redirect_uri: "https://rp/cb".into(), scope: "openid".into(),
        nonce: Some("n".into()), code_challenge: Some("chal".into()),
        code_challenge_method: Some("S256".into()),
        expires_at: Utc::now() + chrono::Duration::seconds(120),
        consumed_at: None, created_at: Utc::now(),
    }).await.unwrap();
    assert!(authz(&store).consume_code(&hash).await.unwrap().is_some());
    // second consume → None (single-use)
    assert!(authz(&store).consume_code(&hash).await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn refresh_rotation_and_reuse_detection() {
    let (pool, _c) = setup_oauth_pool().await;
    let store = PgStore::new(pool);
    let family = Uuid::new_v4();
    let mk = |h: &str| RefreshTokenRecord {
        token_hash: h.into(), family_id: family, client_id: "cli-1".into(),
        user_id: Uuid::new_v4(), tenant_id: Uuid::new_v4(), scope: "openid".into(),
        expires_at: Utc::now() + chrono::Duration::days(30), revoked_at: None, created_at: Utc::now(),
    };
    let h1 = volta_auth_core::crypto::sha256_hex("rt1");
    let h2 = volta_auth_core::crypto::sha256_hex("rt2");
    refresh(&store).save_refresh(mk(&h1)).await.unwrap();
    refresh(&store).save_refresh(mk(&h2)).await.unwrap(); // a later rotation in same family

    // rotate h1 → Rotated (revokes h1)
    assert!(matches!(refresh(&store).rotate_refresh(&h1).await.unwrap(), RefreshOutcome::Rotated(_)));
    // reuse h1 (now revoked) → Reused, and the whole family is revoked
    assert_eq!(refresh(&store).rotate_refresh(&h1).await.unwrap(), RefreshOutcome::Reused);
    // h2 was in the family → now revoked too, so a later rotate also flags reuse
    assert_eq!(refresh(&store).rotate_refresh(&h2).await.unwrap(), RefreshOutcome::Reused);
    // unknown token → NotFound
    assert_eq!(refresh(&store).rotate_refresh("nope").await.unwrap(), RefreshOutcome::NotFound);
}

// ─── RiskDeviceStore (Phase 4c) ────────────────────────────

#[tokio::test]
#[ignore]
async fn risk_device_new_then_known() {
    let (pool, _c) = setup_pool().await;
    sqlx::raw_sql(include_str!("../migrations/030_create_risk_known_devices.sql"))
        .execute(&pool).await.unwrap();
    let store = PgStore::new(pool);
    let user = Uuid::new_v4();
    let dev = volta_auth_core::crypto::sha256_hex("device-cookie-value");

    // first sighting → new (false = not previously known)
    assert!(!RiskDeviceStore::check_and_record(&store, user, &dev).await.unwrap());
    // second sighting → known
    assert!(RiskDeviceStore::check_and_record(&store, user, &dev).await.unwrap());
    // a different device for the same user is still new
    let dev2 = volta_auth_core::crypto::sha256_hex("other-device");
    assert!(!RiskDeviceStore::check_and_record(&store, user, &dev2).await.unwrap());
    // and the same device for a different user is new
    assert!(!RiskDeviceStore::check_and_record(&store, Uuid::new_v4(), &dev).await.unwrap());
}

// ─── UserIdentityStore / account linking (Phase 5) ─────────

fn identities(s: &PgStore) -> &(dyn UserIdentityStore + '_) { s }

#[tokio::test]
#[ignore]
async fn account_linking_multiple_providers() {
    let (pool, _c) = setup_pool().await;
    sqlx::raw_sql(include_str!("../migrations/032_create_user_identities.sql"))
        .execute(&pool).await.unwrap();
    let store = PgStore::new(pool);
    let user = Uuid::new_v4();

    let mk = |prov: &str, sub: &str| UserIdentityRecord {
        id: Uuid::new_v4(), user_id: user, provider: prov.into(), subject: sub.into(),
        email: Some("a@example.com".into()), email_verified: true, created_at: Utc::now(),
    };
    // link google + github to the same user
    identities(&store).link(mk("google", "g-1")).await.unwrap();
    identities(&store).link(mk("github", "h-1")).await.unwrap();
    assert_eq!(identities(&store).count_by_user(user).await.unwrap(), 2);

    // resolve by (provider, subject)
    let found = identities(&store).find_by_subject("github", "h-1").await.unwrap().unwrap();
    assert_eq!(found.user_id, user);
    assert!(identities(&store).find_by_subject("github", "nope").await.unwrap().is_none());

    // re-link same (provider, subject) is idempotent (upsert), not a 2nd row
    identities(&store).link(mk("google", "g-1")).await.unwrap();
    assert_eq!(identities(&store).count_by_user(user).await.unwrap(), 2);

    // unlink one (scoped to the owner); wrong user can't remove it
    let gh = identities(&store).find_by_subject("github", "h-1").await.unwrap().unwrap();
    assert!(!identities(&store).unlink(Uuid::new_v4(), gh.id).await.unwrap());
    assert!(identities(&store).unlink(user, gh.id).await.unwrap());
    assert_eq!(identities(&store).count_by_user(user).await.unwrap(), 1);
}

#[tokio::test]
#[ignore]
async fn session_stepup_marker() {
    let (pool, _c) = setup_pool().await;
    sqlx::raw_sql(include_str!("../migrations/033_create_session_stepup.sql"))
        .execute(&pool).await.unwrap();
    let store = PgStore::new(pool);
    let s: &dyn SessionStepUpStore = &store;
    assert!(!s.is_required("sess-x").await.unwrap());
    s.mark("sess-x").await.unwrap();
    assert!(s.is_required("sess-x").await.unwrap());
    s.mark("sess-x").await.unwrap(); // idempotent
    assert!(s.is_required("sess-x").await.unwrap());
    assert!(!s.is_required("other").await.unwrap());
}
