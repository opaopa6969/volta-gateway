//! End-to-end integration tests for the passwordless registration runtime.
//! Exercises flow record + verification token + notification outbox together.
//! Run: cargo test -p volta-auth-core --features postgres --test registration_runtime_test -- --ignored
#![cfg(feature = "postgres")]

use sqlx::PgPool;
use volta_auth_core::runtime;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::{FlowPersistence, NotificationJobStore};

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
    sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        .execute(&pool)
        .await
        .unwrap();
    for m in [
        include_str!("../migrations/001_create_users.sql"),
        include_str!("../migrations/015_create_user_passkeys.sql"),
        include_str!("../migrations/006_create_auth_flows.sql"),
        include_str!("../migrations/007_create_auth_flow_transitions.sql"),
        include_str!("../migrations/024_create_notification_jobs.sql"),
        include_str!("../migrations/025_create_email_verification_tokens.sql"),
    ] {
        sqlx::raw_sql(m).execute(&pool).await.unwrap();
    }
    (PgStore::new(pool), container)
}

#[tokio::test]
#[ignore]
async fn happy_path_start_verify_completes_and_enqueues_dummy_notification() {
    let (store, _c) = setup().await;

    // Start: flow pending, token issued, ONE notification job on the DUMMY channel.
    let started = runtime::start_registration(&store, "alice@example.com", true, "DUMMY")
        .await
        .unwrap();
    assert_eq!(started.outcome.state, "EmailVerificationPending");
    assert_eq!(
        started.outcome.next_actions,
        vec!["VERIFY_EMAIL", "RESEND_VERIFICATION"]
    );
    let raw = started.dev_token.expect("dev token available in test");

    let jobs = store.claim_pending(10).await.unwrap();
    assert_eq!(
        jobs.len(),
        1,
        "exactly one verification notification enqueued"
    );
    assert_eq!(jobs[0].channel, "DUMMY", "no external channel used");
    assert_eq!(jobs[0].template_id, "email-verification");
    assert_eq!(jobs[0].recipient, "alice@example.com");

    // Verify with the correct token → flow completes.
    let done = runtime::verify_email(&store, &raw).await.unwrap();
    assert_eq!(done.state, "Completed");
    let flow = store.find(started.outcome.flow_id).await.unwrap().unwrap();
    assert_eq!(flow.exit_state.as_deref(), Some("Completed"));
    assert!(flow.completed_at.is_some());

    // Token is one-time: re-verify fails.
    assert!(runtime::verify_email(&store, &raw).await.is_err());
}

#[tokio::test]
#[ignore]
async fn verification_disabled_skips_token_and_notification() {
    let (store, _c) = setup().await;
    let started = runtime::start_registration(&store, "bob@example.com", false, "DUMMY")
        .await
        .unwrap();
    assert_eq!(started.outcome.state, "EmailVerified");
    assert!(
        started.dev_token.is_none(),
        "no token when verification disabled"
    );
    assert!(
        store.claim_pending(10).await.unwrap().is_empty(),
        "no notification enqueued"
    );
}

#[tokio::test]
#[ignore]
async fn wrong_token_is_rejected() {
    let (store, _c) = setup().await;
    runtime::start_registration(&store, "carol@example.com", true, "DUMMY")
        .await
        .unwrap();
    assert!(
        runtime::verify_email(&store, "deadbeef-not-a-real-token")
            .await
            .is_err(),
        "unknown token must be rejected"
    );
}

#[tokio::test]
#[ignore]
async fn resend_is_throttled_then_allowed() {
    let (store, _c) = setup().await;
    runtime::start_registration(&store, "dave@example.com", true, "DUMMY")
        .await
        .unwrap();

    // Within the 60s window → throttled.
    assert!(
        !runtime::resend_verification(&store, "dave@example.com", "DUMMY", 60)
            .await
            .unwrap()
    );
    // 0s interval → allowed, and a fresh job is enqueued.
    assert!(
        runtime::resend_verification(&store, "dave@example.com", "DUMMY", 0)
            .await
            .unwrap()
    );
    // Unknown email → nothing pending → not allowed.
    assert!(
        !runtime::resend_verification(&store, "nobody@example.com", "DUMMY", 0)
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore]
async fn initial_passkey_and_verification_state_commit_once() {
    use volta_auth_core::store::{PasskeyStore, UserStore};
    use volta_auth_core::{crypto::sha256_hex, record::PasskeyRecord};

    let (store, _container) = setup().await;
    let email = "first-passkey@example.test";
    let started = runtime::start_registration(&store, email, true, "DUMMY")
        .await
        .unwrap();
    let hash = sha256_hex(&started.dev_token.unwrap());
    let flow = started.outcome.flow_id;
    assert_eq!(
        store.pending_passkey_signup(&hash).await.unwrap(),
        Some((flow, email.into()))
    );
    let passkey = PasskeyRecord {
        id: uuid::Uuid::new_v4(),
        user_id: uuid::Uuid::new_v4(),
        credential_id: vec![1, 2, 3, 4],
        public_key: vec![5, 6, 7, 8],
        sign_count: 0,
        transports: None,
        name: None,
        aaguid: None,
        backup_eligible: false,
        backup_state: false,
        created_at: chrono::Utc::now(),
        last_used_at: None,
    };
    let (first, second) = tokio::join!(
        store.complete_passkey_signup(flow, &hash, &passkey),
        store.complete_passkey_signup(flow, &hash, &passkey),
    );
    assert_ne!(first.unwrap(), second.unwrap());
    assert_eq!(
        store.find_by_email(email).await.unwrap().unwrap().id,
        passkey.user_id
    );
    assert_eq!(store.list_by_user(passkey.user_id).await.unwrap().len(), 1);
    assert!(store.pending_passkey_signup(&hash).await.unwrap().is_none());

    let again = runtime::start_registration(&store, email, true, "DUMMY")
        .await
        .unwrap();
    let second_hash = sha256_hex(&again.dev_token.unwrap());
    let another_key = PasskeyRecord {
        id: uuid::Uuid::new_v4(),
        user_id: uuid::Uuid::new_v4(),
        ..passkey.clone()
    };
    assert!(!store
        .complete_passkey_signup(again.outcome.flow_id, &second_hash, &another_key)
        .await
        .unwrap());
    assert_eq!(store.list_by_user(passkey.user_id).await.unwrap().len(), 1);
    assert!(store
        .pending_passkey_signup(&second_hash)
        .await
        .unwrap()
        .is_some());
}
