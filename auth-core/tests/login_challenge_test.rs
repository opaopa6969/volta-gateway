//! Integration tests for the Email/SMS OTP login challenge (Phase 5).
//! Run: cargo test -p volta-auth-core --features postgres --test login_challenge_test -- --ignored
#![cfg(feature = "postgres")]

use sqlx::PgPool;
use uuid::Uuid;
use volta_auth_core::runtime;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::{ChallengeVerifyOutcome, NotificationJobStore};

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
        include_str!("../migrations/024_create_notification_jobs.sql"),
        include_str!("../migrations/026_create_login_challenges.sql"),
    ] {
        sqlx::raw_sql(m).execute(&pool).await.unwrap();
    }
    (PgStore::new(pool), container)
}

#[tokio::test]
#[ignore]
async fn otp_issue_enqueues_notification_and_verifies() {
    let (store, _c) = setup().await;
    let user = Uuid::new_v4();

    let start = runtime::issue_login_otp(&store, user, "EMAIL_OTP", "user@example.com", "DUMMY")
        .await
        .unwrap();
    let code = start.dev_code.expect("dev code in test");
    assert_eq!(code.len(), 6, "6-digit OTP");

    // Notification enqueued on the DUMMY channel with the code (no external send).
    let jobs = store.claim_pending(10).await.unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].channel, "DUMMY");
    assert_eq!(jobs[0].template_id, "mfa-code");
    assert_eq!(jobs[0].recipient, "user@example.com");

    // Correct code verifies once.
    assert_eq!(
        runtime::verify_login_otp(&store, user, &code).await.unwrap(),
        ChallengeVerifyOutcome::Verified
    );
    // Consumed → no active challenge.
    assert_eq!(
        runtime::verify_login_otp(&store, user, &code).await.unwrap(),
        ChallengeVerifyOutcome::NotFound
    );
}

#[tokio::test]
#[ignore]
async fn wrong_code_decrements_then_locks() {
    let (store, _c) = setup().await;
    let user = Uuid::new_v4();
    runtime::issue_login_otp(&store, user, "EMAIL_OTP", "u@e.com", "DUMMY").await.unwrap();

    // 5 max attempts: wrong codes decrement, then lock.
    let mut last = ChallengeVerifyOutcome::NotFound;
    for _ in 0..5 {
        last = runtime::verify_login_otp(&store, user, "000000-wrong").await.unwrap();
    }
    // After exhausting attempts → TooManyAttempts.
    assert_eq!(last, ChallengeVerifyOutcome::TooManyAttempts);
    // Even the correct code is now locked out (still TooManyAttempts).
    // (We don't know the real code here; assert the locked state persists.)
    assert!(matches!(
        runtime::verify_login_otp(&store, user, "111111").await.unwrap(),
        ChallengeVerifyOutcome::TooManyAttempts
    ));
}

#[tokio::test]
#[ignore]
async fn no_active_challenge_is_not_found() {
    let (store, _c) = setup().await;
    let user = Uuid::new_v4();
    assert_eq!(
        runtime::verify_login_otp(&store, user, "123456").await.unwrap(),
        ChallengeVerifyOutcome::NotFound
    );
}

#[tokio::test]
#[ignore]
async fn issuing_again_invalidates_prior_challenge() {
    let (store, _c) = setup().await;
    let user = Uuid::new_v4();
    let first = runtime::issue_login_otp(&store, user, "EMAIL_OTP", "u@e.com", "DUMMY")
        .await
        .unwrap()
        .dev_code
        .unwrap();
    // Re-issue → prior challenge consumed.
    let _second = runtime::issue_login_otp(&store, user, "EMAIL_OTP", "u@e.com", "DUMMY").await.unwrap();
    // The first code no longer matches the (new) active challenge.
    assert!(matches!(
        runtime::verify_login_otp(&store, user, &first).await.unwrap(),
        ChallengeVerifyOutcome::WrongCode { .. } | ChallengeVerifyOutcome::NotFound
    ));
}
