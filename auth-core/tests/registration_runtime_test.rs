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
    sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;").execute(&pool).await.unwrap();
    for m in [
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
    assert_eq!(started.outcome.next_actions, vec!["VERIFY_EMAIL", "RESEND_VERIFICATION"]);
    let raw = started.dev_token.expect("dev token available in test");

    let jobs = store.claim_pending(10).await.unwrap();
    assert_eq!(jobs.len(), 1, "exactly one verification notification enqueued");
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
    assert!(started.dev_token.is_none(), "no token when verification disabled");
    assert!(store.claim_pending(10).await.unwrap().is_empty(), "no notification enqueued");
}

#[tokio::test]
#[ignore]
async fn wrong_token_is_rejected() {
    let (store, _c) = setup().await;
    runtime::start_registration(&store, "carol@example.com", true, "DUMMY").await.unwrap();
    assert!(
        runtime::verify_email(&store, "deadbeef-not-a-real-token").await.is_err(),
        "unknown token must be rejected"
    );
}

#[tokio::test]
#[ignore]
async fn resend_is_throttled_then_allowed() {
    let (store, _c) = setup().await;
    runtime::start_registration(&store, "dave@example.com", true, "DUMMY").await.unwrap();

    // Within the 60s window → throttled.
    assert!(!runtime::resend_verification(&store, "dave@example.com", "DUMMY", 60).await.unwrap());
    // 0s interval → allowed, and a fresh job is enqueued.
    assert!(runtime::resend_verification(&store, "dave@example.com", "DUMMY", 0).await.unwrap());
    // Unknown email → nothing pending → not allowed.
    assert!(!runtime::resend_verification(&store, "nobody@example.com", "DUMMY", 0).await.unwrap());
}
