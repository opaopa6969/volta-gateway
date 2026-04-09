mod app;
mod error;
mod handlers;
mod helpers;
mod outbox_worker;
pub mod saml;
mod state;

use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

use volta_auth_core::idp::{IdpClient, IdpConfig};
use volta_auth_core::jwt::{JwtIssuer, JwtVerifier};
use volta_auth_core::store::pg::PgStore;

use crate::state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "volta_auth_server=info".into()),
        )
        .json()
        .init();

    // Config from env vars (Java compat: same env var names)
    let port: u16 = env("PORT", "7070").parse().unwrap();
    let database_url = env("DATABASE_URL", "postgres://localhost/volta");
    let jwt_secret = env("JWT_SECRET", "volta-dev-secret-change-me-in-prod");
    let session_ttl: u64 = env("SESSION_TTL_SECONDS", "28800").parse().unwrap();
    let cookie_domain = env("COOKIE_DOMAIN", "");
    let force_secure = env("FORCE_SECURE_COOKIE", "false") == "true";
    let base_url = env("BASE_URL", &format!("http://localhost:{}", port));
    let state_key = env("STATE_SIGNING_KEY", &jwt_secret);

    // IdP config
    let idp_provider = env("IDP_PROVIDER", "google");
    let idp_client_id = env("IDP_CLIENT_ID", "");
    let idp_client_secret = env("IDP_CLIENT_SECRET", "");

    // Database
    let pool = PgPool::connect(&database_url).await
        .unwrap_or_else(|e| { eprintln!("DB connect failed: {}", e); std::process::exit(1); });

    info!("database connected");

    let db = PgStore::new(pool);

    let idp = IdpClient::new(IdpConfig {
        provider: idp_provider,
        client_id: idp_client_id,
        client_secret: idp_client_secret,
        issuer_url: None,
        auth_url: None,
        token_url: None,
        userinfo_url: None,
        scopes: vec![],
    });

    let state = AppState {
        db,
        idp: Arc::new(idp),
        jwt_issuer: JwtIssuer::new_hs256(jwt_secret.as_bytes(), session_ttl),
        jwt_verifier: JwtVerifier::new_hs256(jwt_secret.as_bytes()),
        cookie_domain,
        session_ttl_secs: session_ttl,
        force_secure_cookie: force_secure,
        base_url,
        state_signing_key: state_key.into_bytes(),
    };

    // Outbox worker — poll every 5s, deliver webhooks
    let outbox_poll: u64 = env("OUTBOX_POLL_SECS", "5").parse().unwrap_or(5);
    outbox_worker::spawn(state.db.clone(), std::time::Duration::from_secs(outbox_poll));

    let router = app::build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!(port = port, "volta-auth-server starting");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
