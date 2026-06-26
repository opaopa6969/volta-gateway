//! Notification worker — polls notification_jobs and delivers via the
//! NotificationService (DUMMY/LOG locally; SMTP/SES in Phase 6). Mirrors the
//! webhook outbox worker: claim → send → log → mark sent / retry / failed.
//! Retries are bounded (5 attempts) and use the store's backoff.

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info};

use volta_auth_core::notification::{NotificationMessage, NotificationService, NotificationTemplate};
use volta_auth_core::record::NotificationLogRecord;
use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::NotificationJobStore;

const MAX_ATTEMPTS: i32 = 5;

pub fn spawn(db: PgStore, notifications: Arc<NotificationService>, poll: Duration) {
    tokio::spawn(async move {
        info!(interval_secs = poll.as_secs(), "notification worker started");
        loop {
            if let Err(e) = poll_once(&db, &notifications).await {
                error!(error = %e, "notification worker error");
            }
            tokio::time::sleep(poll).await;
        }
    });
}

async fn poll_once(db: &PgStore, notifications: &NotificationService) -> Result<(), String> {
    let jobs = db.claim_pending(20).await.map_err(|e| e.to_string())?;
    if jobs.is_empty() {
        return Ok(());
    }
    info!(count = jobs.len(), "delivering notifications");

    for job in jobs {
        let channel = notifications
            .config()
            .default_channel; // fallback
        let channel = volta_auth_core::notification::NotificationChannel::parse(&job.channel)
            .unwrap_or(channel);

        let mut tmpl = NotificationTemplate::new(&job.template_id);
        if let Some(obj) = job.payload.as_object() {
            for (k, v) in obj {
                let val = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
                tmpl.vars.insert(k.clone(), val);
            }
        }
        let msg = NotificationMessage {
            channel,
            to: job.recipient.clone(),
            template: tmpl,
            correlation_id: Some(job.id.to_string()),
        };

        match notifications.send(&msg).await {
            Ok(receipt) => {
                if let Err(e) = db.mark_sent(job.id).await {
                    error!(error = %e, job = %job.id, "mark_sent failed");
                }
                let _ = db
                    .log(NotificationLogRecord {
                        id: 0,
                        job_id: Some(job.id),
                        channel: job.channel.clone(),
                        provider: receipt.provider.as_str().to_string(),
                        recipient: job.recipient.clone(),
                        template_id: job.template_id.clone(),
                        outcome: "sent".into(),
                        message_id: receipt.message_id,
                        error: None,
                        created_at: chrono::Utc::now(),
                    })
                    .await;
            }
            Err(e) => {
                let attempt = job.attempt_count + 1;
                if e.is_retryable() && attempt < MAX_ATTEMPTS {
                    let _ = db.mark_retry(job.id, attempt, &e.to_string()).await;
                } else {
                    let _ = db.mark_failed(job.id, &e.to_string()).await;
                }
                let _ = db
                    .log(NotificationLogRecord {
                        id: 0,
                        job_id: Some(job.id),
                        channel: job.channel.clone(),
                        provider: "-".into(),
                        recipient: job.recipient.clone(),
                        template_id: job.template_id.clone(),
                        outcome: "failed".into(),
                        message_id: None,
                        error: Some(e.to_string()),
                        created_at: chrono::Utc::now(),
                    })
                    .await;
            }
        }
    }
    Ok(())
}
