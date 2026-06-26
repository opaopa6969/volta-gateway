//! Email notification providers (Phase 6).
//!
//! `build_email_sender()` chooses a concrete EMAIL [`NotificationSender`] from
//! `NOTIFICATION_EMAIL_PROVIDER`:
//!   - `SMTP`    → real SMTP relay (rustls), creds + STARTTLS from env
//!   - `MAILPIT` → plain SMTP to localhost:1025 (local dev; no TLS/auth)
//!   - `DUMMY`   → in-memory capture (no send)
//!   - `SES`     → not yet implemented → falls back to LOG (warns)
//!   - anything else / unset → LOG sink (no external send)
//!
//! Templates are rendered by [`render`] — minimal but real subject/body so a
//! configured relay sends a usable message. SMS/LINE remain dummy/log until a
//! provider is wired.

use std::sync::Arc;

use async_trait::async_trait;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use tracing::{info, warn};

use volta_auth_core::notification::dummy::{DummySender, LogSender};
use volta_auth_core::notification::{
    NotificationChannel, NotificationError, NotificationMessage, NotificationProvider,
    NotificationReceipt, NotificationSender, NotificationTemplate,
};

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Render a (subject, body) pair from a template id + vars. Kept intentionally
/// small; a full template engine can replace this without touching senders.
pub fn render(t: &NotificationTemplate) -> (String, String) {
    if let (Some(s), Some(b)) = (&t.subject, &t.body) {
        return (s.clone(), b.clone());
    }
    let get = |k: &str| t.vars.get(k).cloned().unwrap_or_default();
    match t.id.as_str() {
        "email-verification" => (
            "メールアドレスの確認".to_string(),
            format!(
                "以下のトークンでメールアドレスを確認してください:\n\n{}\n\n心当たりがない場合は無視してください。",
                get("token")
            ),
        ),
        "password-reset" => (
            "パスワードリセット".to_string(),
            format!("リセット用トークン:\n\n{}\n", get("token")),
        ),
        "mfa-code" => (
            "認証コード".to_string(),
            format!("認証コード: {}", get("code")),
        ),
        other => (
            format!("通知: {}", other),
            t.vars
                .iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    }
}

/// Real SMTP sender (also used for Mailpit in dev).
pub struct SmtpEmailSender {
    provider: NotificationProvider,
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
}

impl SmtpEmailSender {
    /// Build from env. `mailpit` selects the plain-text localhost dev path.
    pub fn from_env(mailpit: bool) -> Result<Self, String> {
        let from = env("NOTIFICATION_EMAIL_FROM", "no-reply@localhost");
        let host = env("NOTIFICATION_SMTP_HOST", if mailpit { "localhost" } else { "" });
        if host.is_empty() {
            return Err("NOTIFICATION_SMTP_HOST is required for SMTP".into());
        }
        let port: u16 = env("NOTIFICATION_SMTP_PORT", if mailpit { "1025" } else { "587" })
            .parse()
            .map_err(|_| "invalid NOTIFICATION_SMTP_PORT".to_string())?;

        let transport = if mailpit {
            // Mailpit: plain SMTP, no TLS, no auth.
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&host)
                .port(port)
                .build()
        } else {
            let starttls = env("NOTIFICATION_SMTP_STARTTLS", "true") != "false";
            let mut builder = if starttls {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
                    .map_err(|e| format!("smtp starttls: {e}"))?
            } else {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
                    .map_err(|e| format!("smtp relay: {e}"))?
            }
            .port(port);
            let user = env("NOTIFICATION_SMTP_USER", "");
            let pass = env("NOTIFICATION_SMTP_PASS", "");
            if !user.is_empty() {
                builder = builder.credentials(Credentials::new(user, pass));
            }
            builder.build()
        };

        Ok(Self {
            provider: if mailpit { NotificationProvider::Mailpit } else { NotificationProvider::Smtp },
            transport,
            from,
        })
    }
}

#[async_trait]
impl NotificationSender for SmtpEmailSender {
    fn channel(&self) -> NotificationChannel {
        NotificationChannel::Email
    }
    fn provider(&self) -> NotificationProvider {
        self.provider
    }
    async fn send(&self, msg: &NotificationMessage) -> Result<NotificationReceipt, NotificationError> {
        let (subject, body) = render(&msg.template);
        let email = Message::builder()
            .from(self.from.parse().map_err(|e| NotificationError::InvalidConfig(format!("from: {e}")))?)
            .to(msg.to.parse().map_err(|e| NotificationError::SendFailed { retryable: false, reason: format!("to: {e}") })?)
            .subject(subject)
            .body(body)
            .map_err(|e| NotificationError::SendFailed { retryable: false, reason: format!("build: {e}") })?;

        self.transport
            .send(email)
            .await
            // SMTP failures are generally transient → retryable.
            .map_err(|e| NotificationError::SendFailed { retryable: true, reason: e.to_string() })?;

        Ok(NotificationReceipt {
            channel: NotificationChannel::Email,
            provider: self.provider,
            message_id: msg.correlation_id.clone(),
        })
    }
}

/// Select the EMAIL sender from config. Never panics — on misconfig it falls
/// back to the LOG sink (no external send) so the server still boots.
pub fn build_email_sender() -> Arc<dyn NotificationSender> {
    let provider = env("NOTIFICATION_EMAIL_PROVIDER", "LOG").trim().to_ascii_uppercase();
    match provider.as_str() {
        "SMTP" | "MAILPIT" => {
            let mailpit = provider == "MAILPIT";
            match SmtpEmailSender::from_env(mailpit) {
                Ok(s) => {
                    info!(provider = %provider, "email notifications via SMTP");
                    Arc::new(s)
                }
                Err(e) => {
                    warn!(error = %e, "SMTP email sender unavailable — falling back to LOG sink");
                    Arc::new(LogSender::new(NotificationChannel::Email))
                }
            }
        }
        "DUMMY" => Arc::new(DummySender::new(NotificationChannel::Email)),
        "SES" => {
            warn!("NOTIFICATION_EMAIL_PROVIDER=SES not yet implemented — using LOG sink");
            Arc::new(LogSender::new(NotificationChannel::Email))
        }
        _ => Arc::new(LogSender::new(NotificationChannel::Email)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_templates() {
        let t = NotificationTemplate::new("email-verification").var("token", "TOK123");
        let (subject, body) = render(&t);
        assert!(subject.contains("確認"));
        assert!(body.contains("TOK123"));

        let t = NotificationTemplate::new("mfa-code").var("code", "654321");
        let (_s, body) = render(&t);
        assert!(body.contains("654321"));
    }

    #[test]
    fn explicit_subject_body_take_precedence() {
        let mut t = NotificationTemplate::new("anything");
        t.subject = Some("S".into());
        t.body = Some("B".into());
        assert_eq!(render(&t), ("S".to_string(), "B".to_string()));
    }

    #[test]
    fn build_email_sender_defaults_to_log_sink() {
        // No env set → LOG sink, channel EMAIL, never panics.
        std::env::remove_var("NOTIFICATION_EMAIL_PROVIDER");
        let s = build_email_sender();
        assert_eq!(s.channel(), NotificationChannel::Email);
        assert_eq!(s.provider(), NotificationProvider::Log);
    }

    #[test]
    fn build_email_sender_dummy_selectable() {
        std::env::set_var("NOTIFICATION_EMAIL_PROVIDER", "DUMMY");
        let s = build_email_sender();
        assert_eq!(s.provider(), NotificationProvider::DummyEmail);
        std::env::remove_var("NOTIFICATION_EMAIL_PROVIDER");
    }
}
