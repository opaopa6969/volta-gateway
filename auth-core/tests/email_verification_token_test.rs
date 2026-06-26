//! Integration tests for EmailVerificationTokenStore (security-critical).
//! Run: cargo test -p volta-auth-core --features postgres --test email_verification_token_test -- --ignored
#![cfg(feature = "postgres")]

use sqlx::PgPool;
use volta_auth_core::crypto::{random_token_hex, sha256_hex};
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::EmailVerificationTokenStore;

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
    sqlx::raw_sql(include_str!("../migrations/025_create_email_verification_tokens.sql"))
        .execute(&pool)
        .await
        .unwrap();
    (PgStore::new(pool), container)
}

#[tokio::test]
#[ignore]
async fn raw_token_is_never_stored_and_is_one_time() {
    let (store, _c) = setup().await;

    let raw = random_token_hex(32);
    assert_eq!(raw.len(), 64, "32 bytes → 64 hex chars");
    let hash = sha256_hex(&raw);
    assert_ne!(hash, raw, "stored hash must differ from the raw token");

    store.issue("a@b.com", &hash, 15, None).await.unwrap();

    // First consume with the correct hash succeeds and returns the record.
    let rec = store.consume(&hash).await.unwrap().expect("valid token consumes");
    assert_eq!(rec.email, "a@b.com");
    assert!(rec.used_at.is_some());

    // Reuse is rejected (one-time).
    assert!(store.consume(&hash).await.unwrap().is_none(), "used token must not be reusable");

    // An unknown/wrong token never matches.
    assert!(store.consume(&sha256_hex("wrong")).await.unwrap().is_none());
}

#[tokio::test]
#[ignore]
async fn expired_token_cannot_be_consumed() {
    let (store, _c) = setup().await;
    let hash = sha256_hex(&random_token_hex(32));
    // ttl 0 → expires_at = now() at insert; by consume time it is in the past.
    store.issue("a@b.com", &hash, 0, None).await.unwrap();
    assert!(store.consume(&hash).await.unwrap().is_none(), "expired token must be rejected");
}

#[tokio::test]
#[ignore]
async fn resend_is_rate_limited() {
    let (store, _c) = setup().await;
    let hash = sha256_hex(&random_token_hex(32));
    store.issue("a@b.com", &hash, 15, None).await.unwrap(); // sets last_sent_at = now()

    // Immediate resend within the 60s window is throttled.
    assert!(!store.try_mark_resent("a@b.com", 60).await.unwrap(), "resend within window must be blocked");
    // A 0s minimum interval always allows (and bumps resend_count).
    assert!(store.try_mark_resent("a@b.com", 0).await.unwrap());
    // No pending token for an unknown email → not allowed.
    assert!(!store.try_mark_resent("nobody@b.com", 0).await.unwrap());
}

#[tokio::test]
#[ignore]
async fn invalidate_pending_marks_all_used() {
    let (store, _c) = setup().await;
    let h1 = sha256_hex(&random_token_hex(32));
    let h2 = sha256_hex(&random_token_hex(32));
    store.issue("a@b.com", &h1, 15, None).await.unwrap();
    store.issue("a@b.com", &h2, 15, None).await.unwrap();

    let n = store.invalidate_pending("a@b.com").await.unwrap();
    assert_eq!(n, 2, "both pending tokens invalidated");
    assert!(store.consume(&h1).await.unwrap().is_none());
    assert!(store.consume(&h2).await.unwrap().is_none());
}
