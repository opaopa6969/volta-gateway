//! Non-sending senders for local/test: [`DummySender`] (in-memory capture) and
//! [`LogSender`] (tracing only). Neither touches an external service.

use std::sync::Mutex;

use async_trait::async_trait;

use super::{
    NotificationChannel, NotificationError, NotificationMessage, NotificationProvider,
    NotificationReceipt, NotificationSender,
};

/// Records every message in memory so tests can assert what would have been
/// sent. Bound to one channel (so a test can register dummies per channel).
pub struct DummySender {
    channel: NotificationChannel,
    sent: Mutex<Vec<NotificationMessage>>,
}

impl DummySender {
    pub fn new(channel: NotificationChannel) -> Self {
        Self { channel, sent: Mutex::new(Vec::new()) }
    }

    /// Snapshot of captured messages.
    pub fn sent(&self) -> Vec<NotificationMessage> {
        self.sent.lock().expect("dummy sender lock").clone()
    }

    pub fn count(&self) -> usize {
        self.sent.lock().expect("dummy sender lock").len()
    }

    pub fn clear(&self) {
        self.sent.lock().expect("dummy sender lock").clear();
    }

    fn provider_for(channel: NotificationChannel) -> NotificationProvider {
        match channel {
            NotificationChannel::Email => NotificationProvider::DummyEmail,
            NotificationChannel::Sms => NotificationProvider::DummySms,
            NotificationChannel::Line => NotificationProvider::DummyLine,
            NotificationChannel::Log => NotificationProvider::Log,
            NotificationChannel::Dummy => NotificationProvider::Dummy,
        }
    }
}

#[async_trait]
impl NotificationSender for DummySender {
    fn channel(&self) -> NotificationChannel {
        self.channel
    }

    fn provider(&self) -> NotificationProvider {
        Self::provider_for(self.channel)
    }

    async fn send(&self, msg: &NotificationMessage) -> Result<NotificationReceipt, NotificationError> {
        self.sent.lock().expect("dummy sender lock").push(msg.clone());
        Ok(NotificationReceipt {
            channel: self.channel,
            provider: self.provider(),
            message_id: msg.correlation_id.clone(),
        })
    }
}

/// Logs the notification via `tracing` and sends nothing externally. Useful as
/// a visible local sink without storing messages.
pub struct LogSender {
    channel: NotificationChannel,
}

impl LogSender {
    pub fn new(channel: NotificationChannel) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl NotificationSender for LogSender {
    fn channel(&self) -> NotificationChannel {
        self.channel
    }

    fn provider(&self) -> NotificationProvider {
        NotificationProvider::Log
    }

    async fn send(&self, msg: &NotificationMessage) -> Result<NotificationReceipt, NotificationError> {
        // Do NOT log template vars (may contain OTPs / tokens). Log routing
        // metadata only.
        tracing::info!(
            channel = self.channel.as_str(),
            to = %msg.to,
            template = %msg.template.id,
            correlation_id = msg.correlation_id.as_deref().unwrap_or("-"),
            "notification (log sink — not sent externally)"
        );
        Ok(NotificationReceipt {
            channel: self.channel,
            provider: NotificationProvider::Log,
            message_id: msg.correlation_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification::NotificationTemplate;

    #[tokio::test]
    async fn dummy_captures_message() {
        let s = DummySender::new(NotificationChannel::Email);
        let msg = NotificationMessage::new(
            NotificationChannel::Email,
            "a@b.com",
            NotificationTemplate::new("password-reset"),
        )
        .with_correlation_id("flow-1:send");
        let r = s.send(&msg).await.unwrap();
        assert_eq!(r.provider, NotificationProvider::DummyEmail);
        assert_eq!(r.message_id.as_deref(), Some("flow-1:send"));
        assert_eq!(s.count(), 1);
        s.clear();
        assert_eq!(s.count(), 0);
    }

    #[tokio::test]
    async fn log_sender_sends_nothing_but_succeeds() {
        let s = LogSender::new(NotificationChannel::Email);
        let msg = NotificationMessage::new(
            NotificationChannel::Email,
            "a@b.com",
            NotificationTemplate::new("mfa-code"),
        );
        let r = s.send(&msg).await.unwrap();
        assert_eq!(r.provider, NotificationProvider::Log);
    }
}
