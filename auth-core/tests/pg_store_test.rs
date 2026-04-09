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
