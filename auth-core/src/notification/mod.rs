//! Notification abstraction (Phase 1).
//!
//! Decouples "a flow wants to notify the user" from the concrete transport
//! (SMTP / SES / SMS / LINE). Flows never call a provider directly; they build
//! a [`NotificationMessage`] and hand it to a [`NotificationService`], which
//! routes by [`NotificationChannel`] to a registered [`NotificationSender`].
//!
//! Design rules (see docs/auth-flows-and-notifications-design.md):
//! - A channel that is not enabled in config is a hard error
//!   ([`NotificationError::ChannelNotEnabled`]).
//! - local/test never touch external services: use [`dummy::DummySender`]
//!   (captures in memory) or [`dummy::LogSender`] (tracing only).
//! - Providers are swappable trait objects; real SMTP/SES land in later phases.
//! - State-transition logic stays out of here — flows enqueue notification
//!   jobs; a worker calls [`NotificationService::send`] after commit.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

pub mod dummy;

/// Logical delivery channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NotificationChannel {
    Email,
    Sms,
    Line,
    /// Sink that only logs (tracing); never sends externally.
    Log,
    /// Sink that only records in memory (tests); never sends externally.
    Dummy,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Email => "EMAIL",
            Self::Sms => "SMS",
            Self::Line => "LINE",
            Self::Log => "LOG",
            Self::Dummy => "DUMMY",
        }
    }

    /// Case-insensitive parse (config-friendly).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "EMAIL" => Some(Self::Email),
            "SMS" => Some(Self::Sms),
            "LINE" => Some(Self::Line),
            "LOG" => Some(Self::Log),
            "DUMMY" => Some(Self::Dummy),
            _ => None,
        }
    }
}

/// Concrete transport implementation behind a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationProvider {
    // EMAIL
    Smtp,
    Ses,
    Mailpit,
    DummyEmail,
    // SMS
    Sns,
    Twilio,
    DummySms,
    // LINE
    LineMessagingApi,
    DummyLine,
    // generic sinks
    Log,
    Dummy,
}

impl NotificationProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Smtp => "SMTP",
            Self::Ses => "SES",
            Self::Mailpit => "MAILPIT",
            Self::DummyEmail => "DUMMY",
            Self::Sns => "SNS",
            Self::Twilio => "TWILIO",
            Self::DummySms => "DUMMY",
            Self::LineMessagingApi => "LINE_MESSAGING_API",
            Self::DummyLine => "DUMMY",
            Self::Log => "LOG",
            Self::Dummy => "DUMMY",
        }
    }

    /// Parse an email-channel provider from config.
    pub fn parse_email(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SMTP" => Some(Self::Smtp),
            "SES" => Some(Self::Ses),
            "MAILPIT" => Some(Self::Mailpit),
            "DUMMY" => Some(Self::DummyEmail),
            _ => None,
        }
    }

    pub fn parse_sms(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "SNS" => Some(Self::Sns),
            "TWILIO" => Some(Self::Twilio),
            "DUMMY" => Some(Self::DummySms),
            _ => None,
        }
    }

    pub fn parse_line(s: &str) -> Option<Self> {
        match s.trim().to_ascii_uppercase().as_str() {
            "LINE_MESSAGING_API" => Some(Self::LineMessagingApi),
            "DUMMY" => Some(Self::DummyLine),
            _ => None,
        }
    }
}

/// A template reference plus its substitution variables. The template body is
/// resolved by the sender/renderer (later phases); here we carry the id + vars
/// and optionally a pre-rendered subject/body for simple cases.
#[derive(Debug, Clone, Default)]
pub struct NotificationTemplate {
    pub id: String,
    pub vars: HashMap<String, String>,
    pub subject: Option<String>,
    pub body: Option<String>,
}

impl NotificationTemplate {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            vars: HashMap::new(),
            subject: None,
            body: None,
        }
    }

    pub fn var(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.vars.insert(k.into(), v.into());
        self
    }
}

/// One notification to deliver. `to` is channel-specific (email address /
/// phone number / LINE user id).
#[derive(Debug, Clone)]
pub struct NotificationMessage {
    pub channel: NotificationChannel,
    pub to: String,
    pub template: NotificationTemplate,
    /// Stable id for idempotency (e.g. `flow_id:step`) so a retried job does
    /// not double-send.
    pub correlation_id: Option<String>,
}

impl NotificationMessage {
    pub fn new(
        channel: NotificationChannel,
        to: impl Into<String>,
        template: NotificationTemplate,
    ) -> Self {
        Self {
            channel,
            to: to.into(),
            template,
            correlation_id: None,
        }
    }

    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }
}

/// Proof of a (possibly fake) send.
#[derive(Debug, Clone)]
pub struct NotificationReceipt {
    pub channel: NotificationChannel,
    pub provider: NotificationProvider,
    /// Provider message id when available.
    pub message_id: Option<String>,
}

/// Notification failure. `SendFailed.retryable` drives outbox retry policy.
#[derive(Debug, Clone)]
pub enum NotificationError {
    ChannelNotEnabled(NotificationChannel),
    NoSenderForChannel(NotificationChannel),
    SendFailed { retryable: bool, reason: String },
    InvalidConfig(String),
}

impl std::fmt::Display for NotificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChannelNotEnabled(c) => write!(f, "channel not enabled: {}", c.as_str()),
            Self::NoSenderForChannel(c) => write!(f, "no sender registered for channel: {}", c.as_str()),
            Self::SendFailed { retryable, reason } => {
                write!(f, "send failed (retryable={}): {}", retryable, reason)
            }
            Self::InvalidConfig(r) => write!(f, "invalid notification config: {}", r),
        }
    }
}

impl std::error::Error for NotificationError {}

impl NotificationError {
    /// Whether the outbox worker should retry this send.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::SendFailed { retryable: true, .. })
    }
}

impl From<NotificationError> for crate::error::AuthError {
    fn from(e: NotificationError) -> Self {
        crate::error::AuthError::Internal(format!("notification: {}", e))
    }
}

/// One transport for one channel. Implementations must never block the async
/// runtime on external I/O without a timeout (real providers in later phases).
#[async_trait]
pub trait NotificationSender: Send + Sync {
    fn channel(&self) -> NotificationChannel;
    fn provider(&self) -> NotificationProvider;
    async fn send(&self, msg: &NotificationMessage) -> Result<NotificationReceipt, NotificationError>;
}

/// Which channels are usable and which is the default.
#[derive(Debug, Clone)]
pub struct NotificationConfig {
    pub default_channel: NotificationChannel,
    pub enabled_channels: Vec<NotificationChannel>,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        // Safe local/test default: only the in-memory dummy sink.
        Self {
            default_channel: NotificationChannel::Dummy,
            enabled_channels: vec![NotificationChannel::Dummy, NotificationChannel::Log],
        }
    }
}

impl NotificationConfig {
    pub fn is_enabled(&self, channel: NotificationChannel) -> bool {
        self.enabled_channels.contains(&channel)
    }

    /// Parse from a default-channel string and a CSV of enabled channels.
    /// Unknown tokens are an error so misconfiguration fails loudly.
    pub fn parse(default_channel: &str, enabled_csv: &str) -> Result<Self, NotificationError> {
        let default_channel = NotificationChannel::parse(default_channel)
            .ok_or_else(|| NotificationError::InvalidConfig(format!("unknown default channel: {default_channel}")))?;
        let mut enabled = Vec::new();
        for tok in enabled_csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let ch = NotificationChannel::parse(tok)
                .ok_or_else(|| NotificationError::InvalidConfig(format!("unknown channel: {tok}")))?;
            if !enabled.contains(&ch) {
                enabled.push(ch);
            }
        }
        if enabled.is_empty() {
            enabled.push(default_channel);
        }
        Ok(Self { default_channel, enabled_channels: enabled })
    }
}

/// Routes messages to the registered sender for their channel, enforcing the
/// enabled-channels policy.
pub struct NotificationService {
    config: NotificationConfig,
    senders: HashMap<NotificationChannel, Arc<dyn NotificationSender>>,
}

impl NotificationService {
    pub fn new(config: NotificationConfig) -> Self {
        Self { config, senders: HashMap::new() }
    }

    /// Register (or replace) the sender for its channel.
    pub fn register(&mut self, sender: Arc<dyn NotificationSender>) -> &mut Self {
        self.senders.insert(sender.channel(), sender);
        self
    }

    pub fn config(&self) -> &NotificationConfig {
        &self.config
    }

    /// Resolve the channel to use: the explicit request if given, else the
    /// configured default.
    pub fn resolve_channel(&self, requested: Option<NotificationChannel>) -> NotificationChannel {
        requested.unwrap_or(self.config.default_channel)
    }

    /// Send, enforcing the enabled-channels policy. Does not itself retry —
    /// that is the outbox worker's job (later phase) based on
    /// [`NotificationError::is_retryable`].
    pub async fn send(
        &self,
        msg: &NotificationMessage,
    ) -> Result<NotificationReceipt, NotificationError> {
        if !self.config.is_enabled(msg.channel) {
            return Err(NotificationError::ChannelNotEnabled(msg.channel));
        }
        let sender = self
            .senders
            .get(&msg.channel)
            .ok_or(NotificationError::NoSenderForChannel(msg.channel))?;
        sender.send(msg).await
    }
}

#[cfg(test)]
mod tests {
    use super::dummy::DummySender;
    use super::*;

    fn svc_with_dummy() -> (NotificationService, Arc<DummySender>) {
        let cfg = NotificationConfig {
            default_channel: NotificationChannel::Email,
            enabled_channels: vec![NotificationChannel::Email],
        };
        let dummy = Arc::new(DummySender::new(NotificationChannel::Email));
        let mut svc = NotificationService::new(cfg);
        svc.register(dummy.clone());
        (svc, dummy)
    }

    fn msg(channel: NotificationChannel) -> NotificationMessage {
        NotificationMessage::new(
            channel,
            "user@example.com",
            NotificationTemplate::new("email-verification").var("code", "123456"),
        )
    }

    #[tokio::test]
    async fn sends_via_registered_sender_and_captures() {
        let (svc, dummy) = svc_with_dummy();
        let receipt = svc.send(&msg(NotificationChannel::Email)).await.unwrap();
        assert_eq!(receipt.channel, NotificationChannel::Email);
        assert_eq!(dummy.count(), 1);
        assert_eq!(dummy.sent()[0].to, "user@example.com");
        assert_eq!(dummy.sent()[0].template.id, "email-verification");
    }

    #[tokio::test]
    async fn disabled_channel_is_hard_error_and_does_not_send() {
        let (svc, dummy) = svc_with_dummy();
        let err = svc.send(&msg(NotificationChannel::Sms)).await.unwrap_err();
        assert!(matches!(err, NotificationError::ChannelNotEnabled(NotificationChannel::Sms)));
        assert_eq!(dummy.count(), 0);
    }

    #[tokio::test]
    async fn enabled_but_unregistered_channel_errors() {
        let cfg = NotificationConfig {
            default_channel: NotificationChannel::Email,
            enabled_channels: vec![NotificationChannel::Email, NotificationChannel::Sms],
        };
        let svc = NotificationService::new(cfg); // no senders registered
        let err = svc.send(&msg(NotificationChannel::Email)).await.unwrap_err();
        assert!(matches!(err, NotificationError::NoSenderForChannel(NotificationChannel::Email)));
    }

    #[test]
    fn config_parse_rejects_unknown_channel() {
        assert!(NotificationConfig::parse("EMAIL", "EMAIL,BOGUS").is_err());
        let cfg = NotificationConfig::parse("EMAIL", "EMAIL, SMS").unwrap();
        assert!(cfg.is_enabled(NotificationChannel::Email));
        assert!(cfg.is_enabled(NotificationChannel::Sms));
        assert!(!cfg.is_enabled(NotificationChannel::Line));
    }

    #[test]
    fn channel_and_provider_roundtrip() {
        assert_eq!(NotificationChannel::parse("email"), Some(NotificationChannel::Email));
        assert_eq!(NotificationProvider::parse_email("ses"), Some(NotificationProvider::Ses));
        assert_eq!(NotificationProvider::parse_sms("twilio"), Some(NotificationProvider::Twilio));
        assert_eq!(NotificationProvider::parse_line("dummy"), Some(NotificationProvider::DummyLine));
    }

    #[test]
    fn resolve_channel_falls_back_to_default() {
        let (svc, _) = svc_with_dummy();
        assert_eq!(svc.resolve_channel(None), NotificationChannel::Email);
        assert_eq!(svc.resolve_channel(Some(NotificationChannel::Sms)), NotificationChannel::Sms);
    }
}
