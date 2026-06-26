//! Integration tests for the MFA setup runtime (Phase 4): TOTP setup tracked by
//! the mfa_setup flow, reusing existing totp + MfaStore + RecoveryCodeStore.
//! Run: cargo test -p volta-auth-core --features postgres --test mfa_setup_test -- --ignored
#![cfg(feature = "postgres")]

use sqlx::PgPool;
use uuid::Uuid;
use volta_auth_core::runtime;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::{MfaStore, RecoveryCodeStore};

async fn setup() -> (
    PgStore,
    testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>,
) {
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres::Postgres;

    let container = Postgres::default().start().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{}/postgres", port);
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;").execute(&pool).await.unwrap();
    for m in [
        include_str!("../migrations/001_create_users.sql"),
        include_str!("../migrations/002_create_tenants.sql"),
        include_str!("../migrations/006_create_auth_flows.sql"),
        include_str!("../migrations/007_create_auth_flow_transitions.sql"),
        include_str!("../migrations/009_create_user_mfa.sql"),
        include_str!("../migrations/010_create_mfa_recovery_codes.sql"),
        include_str!("../migrations/027_user_mfa_unique_index.sql"),
    ] {
        sqlx::raw_sql(m).execute(&pool).await.unwrap();
    }
    (PgStore::new(pool), container)
}

async fn make_user(store: &PgStore) -> Uuid {
    use volta_auth_core::record::UserRecord;
    use volta_auth_core::store::UserStore;
    let id = Uuid::new_v4();
    UserStore::upsert(
        store,
        UserRecord {
            id,
            email: format!("{}@example.com", id),
            display_name: Some("U".into()),
            google_sub: Some(id.to_string()),
            created_at: chrono::Utc::now(),
            is_active: true,
            locale: Some("ja".into()),
            deleted_at: None,
        },
    )
    .await
    .unwrap();
    id
}

/// Compute the current valid TOTP code the way verify_totp expects: over the
/// base32 secret STRING bytes (matches the existing handler's encoding).
fn current_code(secret: &str) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp_lite::totp_custom::<totp_lite::Sha1>(30, 6, secret.as_bytes(), now / 30)
}

#[tokio::test]
#[ignore]
async fn setup_stores_inactive_then_confirm_activates_and_issues_recovery_codes() {
    let (store, _c) = setup().await;
    let user = make_user(&store).await;

    let start = runtime::start_mfa_setup(&store, user).await.unwrap();
    // Secret is stored but NOT active until confirmed.
    assert!(!MfaStore::has_active(&store, user).await.unwrap(), "must be inactive before confirm");
    assert!(MfaStore::find_any(&store, user, "totp").await.unwrap().is_some());

    // Wrong code does not activate.
    assert!(runtime::confirm_mfa_setup(&store, user, start.flow_id, "000000").await.is_err());
    assert!(!MfaStore::has_active(&store, user).await.unwrap());

    // Correct current code activates + issues recovery codes.
    let code = current_code(&start.secret);
    let confirmed = runtime::confirm_mfa_setup(&store, user, start.flow_id, &code).await.unwrap();
    assert!(MfaStore::has_active(&store, user).await.unwrap(), "active after confirm");
    assert_eq!(confirmed.recovery_codes.len(), 10);

    // Recovery codes are stored hashed (count_unused = 10) and consumable.
    assert_eq!(RecoveryCodeStore::count_unused(&store, user).await.unwrap(), 10);
    let first = &confirmed.recovery_codes[0];
    let hash = volta_auth_core::crypto::sha256_hex(first);
    assert!(RecoveryCodeStore::consume(&store, user, &hash).await.unwrap());
    assert_eq!(RecoveryCodeStore::count_unused(&store, user).await.unwrap(), 9);
}

#[tokio::test]
#[ignore]
async fn confirm_without_setup_is_not_found() {
    let (store, _c) = setup().await;
    let user = make_user(&store).await;
    assert!(runtime::confirm_mfa_setup(&store, user, Uuid::new_v4(), "123456").await.is_err());
}
