//! Integration tests for the notification outbox (NotificationJobStore).
//! Run: cargo test -p volta-auth-core --features postgres --test notification_job_test -- --ignored
#![cfg(feature = "postgres")]

use sqlx::PgPool;
use volta_auth_core::record::NotificationLogRecord;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::NotificationJobStore;

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

    // gen_random_uuid() lives in pgcrypto on older PG images.
    sqlx::raw_sql("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
        .execute(&pool)
        .await
        .unwrap();

    sqlx::raw_sql(include_str!("../migrations/024_create_notification_jobs.sql"))
        .execute(&pool)
        .await
        .unwrap();

    (PgStore::new(pool), container)
}

#[tokio::test]
#[ignore]
async fn enqueue_is_idempotent_on_correlation_id() {
    let (store, _c) = setup().await;

    let id1 = store
        .enqueue("EMAIL", "a@b.com", "email-verification", serde_json::json!({"k": "v"}), Some("flow-1:send"))
        .await
        .unwrap();
    // Same correlation_id → same job id (no duplicate).
    let id2 = store
        .enqueue("EMAIL", "a@b.com", "email-verification", serde_json::json!({}), Some("flow-1:send"))
        .await
        .unwrap();
    assert_eq!(id1, id2, "duplicate correlation_id must not create a new job");

    // NULL correlation_id always inserts a fresh job.
    let id3 = store.enqueue("EMAIL", "x@y.com", "mfa-code", serde_json::json!({}), None).await.unwrap();
    let id4 = store.enqueue("EMAIL", "x@y.com", "mfa-code", serde_json::json!({}), None).await.unwrap();
    assert_ne!(id3, id4, "NULL correlation_id should not collapse jobs");
}

#[tokio::test]
#[ignore]
async fn claim_mark_sent_and_retry_lifecycle() {
    let (store, _c) = setup().await;

    let id = store
        .enqueue("EMAIL", "a@b.com", "password-reset", serde_json::json!({}), Some("pr-1:send"))
        .await
        .unwrap();

    // Pending job is claimable.
    let pending = store.claim_pending(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, id);
    assert_eq!(pending[0].status, "pending");

    // Retry reschedules into the future → no longer immediately claimable.
    store.mark_retry(id, 1, "smtp timeout").await.unwrap();
    let pending = store.claim_pending(10).await.unwrap();
    assert!(pending.is_empty(), "retried job must be deferred to a future next_attempt_at");

    // Mark sent → terminal, not claimable.
    store.mark_sent(id).await.unwrap();
    let pending = store.claim_pending(10).await.unwrap();
    assert!(pending.is_empty());

    // A delivery log row can be recorded.
    store
        .log(NotificationLogRecord {
            id: 0, // BIGSERIAL — ignored on insert
            job_id: Some(id),
            channel: "EMAIL".into(),
            provider: "DUMMY".into(),
            recipient: "a@b.com".into(),
            template_id: "password-reset".into(),
            outcome: "sent".into(),
            message_id: Some("pr-1:send".into()),
            error: None,
            created_at: chrono::Utc::now(),
        })
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn mark_failed_is_not_claimable() {
    let (store, _c) = setup().await;
    let id = store.enqueue("SMS", "+100", "mfa-code", serde_json::json!({}), None).await.unwrap();
    store.mark_failed(id, "provider disabled").await.unwrap();
    assert!(store.claim_pending(10).await.unwrap().is_empty());
}
