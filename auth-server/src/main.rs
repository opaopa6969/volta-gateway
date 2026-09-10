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

    // IdP config
    let idp_provider = env("IDP_PROVIDER", "google");
    let idp_client_id = env("IDP_CLIENT_ID", "");
    let idp_client_secret = env("IDP_CLIENT_SECRET", "");

    // Database
    let pool = PgPool::connect(&database_url).await.unwrap_or_else(|e| {
        eprintln!("DB connect failed: {}", e);
        std::process::exit(1);
    });

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

#[cfg(test)]
mod tests {
    use super::meant_for_us;

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
