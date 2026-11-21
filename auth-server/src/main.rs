pub mod aaguid;
mod app;
pub mod auth_events;
mod error;
mod handlers;
mod helpers;
pub mod local_bypass;
mod notification_providers;
mod notification_worker;
pub mod op_keys;
mod outbox_worker;
pub mod pagination;
pub mod rate_limit;
mod return_to;
pub mod saml;
pub mod saml_dsig;
pub mod saml_sig;
pub mod security;
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
    let port: u16 = env("PORT", "7070").parse().unwrap_or_else(|e| {
        eprintln!("PORT: invalid integer ({e})");
        std::process::exit(1);
    });
    let database_url = env("DATABASE_URL", "postgres://localhost/volta");
    let jwt_secret = env("JWT_SECRET", "volta-dev-secret-change-me-in-prod");
    let session_ttl: u64 = env("SESSION_TTL_SECONDS", "28800")
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("SESSION_TTL_SECONDS: invalid integer ({e})");
            std::process::exit(1);
        });
    let cookie_domain = env("COOKIE_DOMAIN", "");
    let force_secure = env("FORCE_SECURE_COOKIE", "false") == "true";
    let base_url = env("BASE_URL", &format!("http://localhost:{}", port));
    let state_key = env("STATE_SIGNING_KEY", &jwt_secret);

    // IdP config. Without IDP_ISSUER_URL / IDP_*_URL this is the built-in
    // provider table exactly as before (production: IDP_PROVIDER=google).
    let mut idp_config = idp_config_from(|k| std::env::var(k).ok());
    if idp_config.needs_discovery() {
        let issuer = idp_config.issuer_url.clone().unwrap_or_default();
        match volta_auth_core::idp::discover(&issuer).await {
            Ok(doc) => match idp_config.apply_discovery(&doc) {
                Ok(()) => info!(issuer = %doc.issuer, "OIDC discovery applied"),
                Err(e) => {
                    eprintln!("IDP_ISSUER_URL: {e}");
                    std::process::exit(1);
                }
            },
            // Do not take the whole auth-server down when the IdP is briefly
            // unreachable (compose start order): magic link / passkey still work,
            // and the IdP login fails visibly until the next restart.
            Err(e) => tracing::error!("{e}; IdP login is unavailable until restart"),
        }
    }

    // Database
    let pool = PgPool::connect(&database_url).await.unwrap_or_else(|e| {
        eprintln!("DB connect failed: {}", e);
        std::process::exit(1);
    });

    info!("database connected");

    // Optional: apply auth-core/migrations at startup (AUTH_AUTO_MIGRATE=true).
    // Off by default — production manages its schema by hand.
    if env_flag(&env("AUTH_AUTO_MIGRATE", "false")) {
        if let Err(e) = auto_migrate(&pool).await {
            eprintln!("AUTH_AUTO_MIGRATE: {e}");
            std::process::exit(1);
        }
    }

    let db = PgStore::new(pool);

    let idp = IdpClient::new(idp_config);

    // Backlog P2 #9: validate every flow descriptor before serving traffic.
    // Any violation (unreachable state, cycle in Auto/Branch graph, multi-
    // external edge, terminal with outgoing, requires/produces mismatch, or
    // duplicate @FlowData alias) fails the process.
    let descriptors = handlers::viz::flow_descriptors();
    for desc in &descriptors {
        if let Err(errors) = volta_auth_core::flow::validate::validate(desc) {
            for err in &errors {
                tracing::error!(flow = desc.name, "flow validation failed: {:?}", err);
            }
            eprintln!(
                "flow '{}' failed validation with {} error(s)",
                desc.name,
                errors.len()
            );
            std::process::exit(1);
        }
    }
    // Rule #7 cross-flow: every @FlowData alias must be globally unique.
    {
        let refs: Vec<&volta_auth_core::flow::validate::FlowDescriptor> =
            descriptors.iter().collect();
        let alias_errors = volta_auth_core::flow::validate::validate_global_aliases(&refs);
        if !alias_errors.is_empty() {
            for err in &alias_errors {
                tracing::error!("cross-flow alias validation failed: {:?}", err);
            }
            eprintln!(
                "cross-flow alias validation failed with {} error(s)",
                alias_errors.len()
            );
            std::process::exit(1);
        }
    }
    info!("flow definitions validated");

    let local_bypass = Arc::new(local_bypass::LocalNetworkBypass::from_env());
    if local_bypass.is_empty() {
        info!("local_bypass disabled (LOCAL_BYPASS_CIDRS is empty)");
    } else {
        info!("local_bypass enabled; forwarded IPs require LOCAL_BYPASS_TRUSTED_PROXY_CIDRS");
    }

    // P1 #7: optional Redis pub/sub bridge for SSE fan-out.
    let mut event_bus = auth_events::AuthEventBus::new();
    let redis_url = env("REDIS_URL", "");
    if !redis_url.is_empty() {
        let channel = env("REDIS_CHANNEL", auth_events::DEFAULT_CHANNEL);
        match auth_events::spawn_redis_bridge(&redis_url, channel, event_bus.clone()).await {
            Ok((publisher, _handle)) => {
                info!(channel = publisher.channel(), "redis auth-event bridge up");
                event_bus = event_bus.with_redis(publisher);
            }
            Err(e) => {
                tracing::warn!(
                    "redis auth-event bridge failed, continuing in-process only: {}",
                    e
                );
            }
        }
    } else {
        info!("redis auth-event bridge disabled (REDIS_URL unset)");
    }

    // P1 #5: optional WebAuthn service. Activated by `WEBAUTHN_RP_ID` +
    // `WEBAUTHN_RP_ORIGIN`. Without both set, passkey handlers return 503.
    let rp_id = env("WEBAUTHN_RP_ID", "");
    let rp_origin = env("WEBAUTHN_RP_ORIGIN", "");
    let passkey_service = if !rp_id.is_empty() && !rp_origin.is_empty() {
        match url::Url::parse(&rp_origin) {
            Ok(origin) => match volta_auth_core::passkey::PasskeyService::new(&rp_id, &origin) {
                Ok(svc) => {
                    info!(rp_id = %rp_id, "webauthn configured");
                    Some(Arc::new(svc))
                }
                Err(e) => {
                    tracing::warn!("webauthn init failed, passkey disabled: {}", e);
                    None
                }
            },
            Err(e) => {
                tracing::warn!("WEBAUTHN_RP_ORIGIN invalid URL, passkey disabled: {}", e);
                None
            }
        }
    } else {
        info!("webauthn disabled (WEBAUTHN_RP_ID / WEBAUTHN_RP_ORIGIN unset)");
        None
    };

    // Notification subsystem (Phase 2). Channels/providers are config-driven;
    // local/test default to DUMMY/LOG so nothing is sent externally. Real
    // SMTP/SES senders are registered in Phase 6 (provider = SMTP/SES/MAILPIT).
    let notify_default = env("NOTIFICATION_DEFAULT_CHANNEL", "DUMMY");
    let notify_enabled = env("NOTIFICATION_ENABLED_CHANNELS", "DUMMY,LOG,EMAIL");
    let notif_config =
        volta_auth_core::notification::NotificationConfig::parse(&notify_default, &notify_enabled)
            .unwrap_or_else(|e| {
                eprintln!("invalid notification config: {}", e);
                std::process::exit(1);
            });
    let notifications = {
        use volta_auth_core::notification::dummy::{DummySender, LogSender};
        use volta_auth_core::notification::{NotificationChannel, NotificationService};
        let mut svc = NotificationService::new(notif_config);
        svc.register(Arc::new(DummySender::new(NotificationChannel::Dummy)));
        svc.register(Arc::new(LogSender::new(NotificationChannel::Log)));
        // EMAIL: real provider (SMTP/MAILPIT/DUMMY) chosen by
        // NOTIFICATION_EMAIL_PROVIDER; falls back to LOG sink (no external send).
        svc.register(notification_providers::build_email_sender());
        // SMS (Twilio) / LINE (Messaging API): real providers when configured,
        // else DUMMY/LOG (no external send). SNS/SES remain LOG fallbacks.
        svc.register(notification_providers::build_sms_sender());
        svc.register(notification_providers::build_line_sender());
        Arc::new(svc)
    };
    let notify_channel = notify_default.trim().to_ascii_uppercase();
    let email_verification_enabled = env("AUTH_EMAIL_VERIFICATION", "enabled") != "disabled";

    // Phase 3a: ensure an OP RS256 signing key exists and build its issuer.
    // Independent of the internal HS256 session issuer (which the gateway
    // verifies with the shared secret). `None` → OP token signing unavailable.
    let op_issuer = op_keys::bootstrap_op_issuer(&db, session_ttl).await;

    let return_to_policy = return_to::ReturnToPolicy::from_env(&cookie_domain, &base_url);

    // Cross-tenant admin APIs (all tenants / all users / signing keys / ...) are
    // limited to explicitly listed system administrators. Unset = nobody.
    let system_admins = helpers::SystemAdmins::from_env();
    if system_admins.is_empty() {
        info!("SYSTEM_ADMIN_EMAILS unset — cross-tenant admin APIs are disabled");
    } else {
        info!(
            count = system_admins.len(),
            "system administrators configured"
        );
    }

    let state = AppState {
        db,
        idp: Arc::new(idp),
        jwt_issuer: JwtIssuer::new_hs256(jwt_secret.as_bytes(), session_ttl),
        jwt_verifier: JwtVerifier::new_hs256(jwt_secret.as_bytes()),
        op_issuer,
        cookie_domain,
        session_ttl_secs: session_ttl,
        force_secure_cookie: force_secure,
        base_url,
        state_signing_key: state_key.into_bytes(),
        local_bypass,
        auth_events: event_bus,
        // Backlog P0 #1: AES-GCM cipher for PKCE verifier storage. Reuses
        // JWT_SECRET when KEY_CIPHER_MASTER_KEY is unset, so existing deployments
        // boot without extra configuration.
        key_cipher: Arc::new(volta_auth_core::crypto::KeyCipher::from_env()),
        passkey: passkey_service,
        notifications: notifications.clone(),
        notify_channel,
        email_verification_enabled,
        passkey_signup_enabled: env("AUTH_PASSKEY_SIGNUP_ENABLED", "false") == "true",
        return_to: Arc::new(return_to_policy),
        system_admins: Arc::new(system_admins),
    };

    // Outbox worker — poll every 5s, deliver webhooks
    let outbox_poll: u64 = env("OUTBOX_POLL_SECS", "5").parse().unwrap_or(5);
    outbox_worker::spawn(
        state.db.clone(),
        std::time::Duration::from_secs(outbox_poll),
    );

    // Notification worker — poll notification_jobs, deliver via NotificationService.
    let notif_poll: u64 = env("NOTIFICATION_POLL_SECS", "5").parse().unwrap_or(5);
    notification_worker::spawn(
        state.db.clone(),
        notifications,
        std::time::Duration::from_secs(notif_poll),
    );

    let router = app::build_router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!(port = port, "volta-auth-server starting");

    // Prefer the listener systemd already holds (socket activation). systemd keeps
    // the socket across restarts, so clients are never refused while this process is
    // being replaced — they just wait in the backlog until the new one accepts.
    //
    // Without it, :7072 disappears for a moment on every deploy. volta-index proxies
    // browser terminals at /term/ and calls this server on *every* request, so that
    // gap drops the WebSocket: the terminal stays on screen but stops taking input.
    // Measured 2026-09-11 — three restarts right after gateway merges (06:48 / 07:40
    // / 08:03), each one matching a burst of `auth-server に繋がりません` in the hub log.
    let listener = match systemd_listener() {
        Some(inherited) => {
            info!("adopting the listener passed by systemd (socket activation)");
            tokio::net::TcpListener::from_std(inherited).unwrap_or_else(|e| {
                eprintln!("failed to adopt the systemd listener: {e}");
                std::process::exit(1);
            })
        }
        // No socket unit in front of us: bind ourselves, exactly as before.
        None => tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| {
                eprintln!("failed to bind {addr}: {e} (port already in use?)");
                std::process::exit(1);
            }),
    };
    // `into_make_service_with_connect_info` makes peer SocketAddr available to
    // handlers/middleware via `ConnectInfo<SocketAddr>` — needed for the IP-keyed
    // rate limiter (#7, #10).
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    // Finish the requests already in flight before exiting. Holding the socket is
    // pointless if the responses being written are cut off mid-flight.
    .with_graceful_shutdown(shutdown_signal())
    .await
    .unwrap();
}

/// The listener systemd passed us via socket activation, if there is one.
///
/// Ignores the variables unless `LISTEN_PID` names *this* process — otherwise a
/// child inheriting them would grab fd 3, which is something else entirely. That
/// check is also why we do not unset them: any child is already excluded by pid.
fn systemd_listener() -> Option<std::net::TcpListener> {
    use std::os::fd::FromRawFd;

    // systemd hands the fds out starting at 3; this unit is given exactly one.
    const LISTEN_FDS_START: i32 = 3;

    if !meant_for_us(
        std::env::var("LISTEN_PID").ok().as_deref(),
        std::env::var("LISTEN_FDS").ok().as_deref(),
        std::process::id(),
    ) {
        return None;
    }
    // SAFETY: systemd guarantees fd 3 is an open, listening socket, and nothing
    // else in this process touches that descriptor.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(LISTEN_FDS_START) };
    // tokio drives it in non-blocking mode; systemd hands it over blocking.
    listener.set_nonblocking(true).unwrap_or_else(|e| {
        eprintln!("failed to set the systemd listener non-blocking: {e}");
        std::process::exit(1);
    });
    Some(listener)
}

/// Whether `LISTEN_PID` / `LISTEN_FDS` describe a socket handed to *this* process.
///
/// Both variables are inherited by children, and fd 3 means something else entirely
/// over there — hence the pid check rather than merely looking for `LISTEN_FDS`.
fn meant_for_us(listen_pid: Option<&str>, listen_fds: Option<&str>, my_pid: u32) -> bool {
    let Some(pid) = listen_pid.and_then(|v| v.parse::<u32>().ok()) else {
        return false;
    };
    let Some(count) = listen_fds.and_then(|v| v.parse::<i32>().ok()) else {
        return false;
    };
    pid == my_pid && count >= 1
}

/// Resolves once the service manager asks us to stop.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to listen for SIGTERM: {e}");
            return;
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to listen for SIGINT: {e}");
            return;
        }
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    info!("shutdown signal received — finishing in-flight requests");
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// `1` / `true` / `yes` / `on` (case-insensitive).
fn env_flag(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Build the IdP config from env-style lookups.
///
/// | var | effect |
/// |---|---|
/// | `IDP_PROVIDER` | built-in provider (`google` default, `github`, `microsoft`, …) or any name for a generic OIDC IdP |
/// | `IDP_CLIENT_ID` / `IDP_CLIENT_SECRET` | OAuth client |
/// | `IDP_ISSUER_URL` | OIDC issuer: enables discovery + `id_token` verification |
/// | `IDP_AUTH_URL` / `IDP_TOKEN_URL` / `IDP_USERINFO_URL` / `IDP_JWKS_URL` | explicit endpoints (win over discovery) |
/// | `IDP_SCOPES` | space- or comma-separated scopes (default: provider's) |
/// | `IDP_DISPLAY_NAME` | login button label |
///
/// Blank values count as unset, so an env file line `IDP_ISSUER_URL=` keeps
/// the built-in behaviour.
fn idp_config_from(get: impl Fn(&str) -> Option<String>) -> IdpConfig {
    let opt = |k: &str| {
        get(k)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    IdpConfig {
        provider: opt("IDP_PROVIDER").unwrap_or_else(|| "google".into()),
        client_id: get("IDP_CLIENT_ID").unwrap_or_default(),
        client_secret: get("IDP_CLIENT_SECRET").unwrap_or_default(),
        issuer_url: opt("IDP_ISSUER_URL"),
        auth_url: opt("IDP_AUTH_URL"),
        token_url: opt("IDP_TOKEN_URL"),
        userinfo_url: opt("IDP_USERINFO_URL"),
        scopes: opt("IDP_SCOPES")
            .map(|s| {
                s.split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|x| !x.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
        jwks_url: opt("IDP_JWKS_URL"),
        display_name: opt("IDP_DISPLAY_NAME"),
    }
}

/// Apply `auth-core/migrations` (embedded at build time) with sqlx's migrator.
///
/// sqlx records applied versions in `_sqlx_migrations`. A database whose schema
/// was created by hand (the production one: `users` exists, no
/// `_sqlx_migrations`) is refused instead of having every migration re-run on
/// top of it.
async fn auto_migrate(pool: &PgPool) -> Result<(), String> {
    let (tracked, has_schema): (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('public._sqlx_migrations') IS NOT NULL, \
                to_regclass('public.users') IS NOT NULL",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| format!("schema check failed: {e}"))?;
    if let Some(reason) = refuse_auto_migrate(tracked, has_schema) {
        return Err(reason.into());
    }
    sqlx::migrate!("../auth-core/migrations")
        .run(pool)
        .await
        .map_err(|e| format!("migration failed: {e}"))?;
    info!("auth-core migrations applied (AUTH_AUTO_MIGRATE)");
    Ok(())
}

/// Why auto-migration must not touch this database, if it must not.
fn refuse_auto_migrate(tracked: bool, has_schema: bool) -> Option<&'static str> {
    (!tracked && has_schema).then_some(
        "the database already has auth tables but no _sqlx_migrations history \
         (schema managed by hand); refusing to re-apply migrations. \
         Unset AUTH_AUTO_MIGRATE for this database.",
    )
}

#[cfg(test)]
mod tests {
    use super::{env_flag, idp_config_from, meant_for_us, refuse_auto_migrate};
    use std::collections::HashMap;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn production_idp_env_builds_the_same_config_as_before() {
        // IDP_PROVIDER=google + client credentials, nothing else.
        let c = idp_config_from(lookup(&[
            ("IDP_PROVIDER", "google"),
            ("IDP_CLIENT_ID", "cid"),
            ("IDP_CLIENT_SECRET", "secret"),
        ]));
        assert_eq!(c.provider, "google");
        assert_eq!(c.client_id, "cid");
        assert_eq!(c.client_secret, "secret");
        assert!(c.issuer_url.is_none());
        assert!(c.auth_url.is_none() && c.token_url.is_none() && c.userinfo_url.is_none());
        assert!(c.jwks_url.is_none() && c.display_name.is_none());
        assert!(c.scopes.is_empty());
        assert!(!c.needs_discovery());
    }

    #[test]
    fn idp_provider_defaults_to_google() {
        let c = idp_config_from(lookup(&[]));
        assert_eq!(c.provider, "google");
        assert!(!c.needs_discovery());
    }

    #[test]
    fn generic_oidc_from_env() {
        let c = idp_config_from(lookup(&[
            ("IDP_PROVIDER", "oidc"),
            ("IDP_ISSUER_URL", "https://idp.example.com/realms/x"),
            ("IDP_SCOPES", "openid, email profile"),
            ("IDP_DISPLAY_NAME", "Keycloak"),
        ]));
        assert_eq!(
            c.issuer_url.as_deref(),
            Some("https://idp.example.com/realms/x")
        );
        assert_eq!(c.scopes, vec!["openid", "email", "profile"]);
        assert_eq!(c.button_label(), "Keycloak");
        assert!(c.needs_discovery());
    }

    #[test]
    fn blank_idp_values_count_as_unset() {
        let c = idp_config_from(lookup(&[("IDP_PROVIDER", ""), ("IDP_ISSUER_URL", " ")]));
        assert_eq!(c.provider, "google");
        assert!(c.issuer_url.is_none());
    }

    #[test]
    fn auto_migrate_flag_is_off_unless_explicit() {
        assert!(!env_flag("false"));
        assert!(!env_flag(""));
        assert!(env_flag("true"));
        assert!(env_flag("1"));
        assert!(env_flag("ON"));
    }

    #[test]
    fn auto_migrate_refuses_a_hand_managed_schema() {
        // Production DB: tables exist, no _sqlx_migrations.
        assert!(refuse_auto_migrate(false, true).is_some());
        // Fresh DB, or one created by a previous auto-migrate.
        assert!(refuse_auto_migrate(false, false).is_none());
        assert!(refuse_auto_migrate(true, true).is_none());
    }

    #[test]
    fn adopts_the_socket_only_when_systemd_named_this_process() {
        assert!(meant_for_us(Some("42"), Some("1"), 42));
        assert!(
            meant_for_us(Some("42"), Some("2"), 42),
            "more than one fd is fine"
        );
    }

    #[test]
    fn ignores_variables_inherited_by_a_child() {
        // A child sees the parent's LISTEN_PID/LISTEN_FDS, but its fd 3 is not the
        // socket. Adopting it there would serve requests off an unrelated descriptor.
        assert!(!meant_for_us(Some("42"), Some("1"), 43));
    }

    #[test]
    fn falls_back_to_binding_when_there_is_no_socket_unit() {
        assert!(!meant_for_us(None, None, 42));
        assert!(!meant_for_us(None, Some("1"), 42));
        assert!(!meant_for_us(Some("42"), None, 42));
        assert!(!meant_for_us(Some("42"), Some("0"), 42), "no fd was passed");
    }

    #[test]
    fn unparsable_values_never_reach_the_raw_fd() {
        assert!(!meant_for_us(Some(""), Some("1"), 42));
        assert!(!meant_for_us(Some("42"), Some(""), 42));
        assert!(!meant_for_us(Some("not-a-pid"), Some("1"), 42));
        assert!(!meant_for_us(Some("42"), Some("not-a-count"), 42));
        assert!(!meant_for_us(Some("-1"), Some("1"), 42));
    }
}
