//! Outbox Worker — polls pending outbox events, delivers to matching webhooks.
//!
//! Pattern: claim pending → find matching webhooks → HTTP POST → record delivery → mark published.
//! Retries with exponential backoff (30s * attempt_count).

use std::time::Duration;
use tracing::{info, warn, error};
use uuid::Uuid;

use volta_auth_core::store::pg::PgStore;
use volta_auth_core::store::{OutboxStore, WebhookStore, WebhookDeliveryStore};

/// Spawn the outbox worker as a background task.
pub fn spawn(db: PgStore, poll_interval: Duration) {
    tokio::spawn(async move {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        info!(interval_secs = poll_interval.as_secs(), "outbox worker started");

        loop {
            if let Err(e) = poll_and_deliver(&db, &http).await {
                error!(error = %e, "outbox worker error");
            }
            tokio::time::sleep(poll_interval).await;
        }
    });
}

async fn poll_and_deliver(db: &PgStore, http: &reqwest::Client) -> Result<(), String> {
    let events = OutboxStore::claim_pending(db, 20).await
        .map_err(|e| format!("claim: {}", e))?;

    if events.is_empty() {
        return Ok(());
    }

    info!(count = events.len(), "processing outbox events");

    for event in &events {
        let tenant_id = match event.tenant_id {
            Some(tid) => tid,
            None => {
                // No tenant — mark as published (system event)
                OutboxStore::mark_published(db, event.id).await
                    .map_err(|e| format!("mark: {}", e))?;
                continue;
            }
        };

        // Find webhooks for this tenant that subscribe to this event type
        let webhooks = WebhookStore::list_by_tenant(db, tenant_id).await
            .map_err(|e| format!("webhooks: {}", e))?;

        let matching: Vec<_> = webhooks.iter()
            .filter(|w| w.is_active && w.events.split(',').any(|e| e.trim() == event.event_type || e.trim() == "*"))
            .collect();

        let mut all_ok = true;

        for wh in &matching {
            let result = deliver(http, &wh.endpoint_url, &wh.secret, &event.event_type, &event.payload).await;

            let (status, status_code, response_body) = match &result {
                Ok((code, body)) => ("success".to_string(), Some(*code), Some(body.clone())),
                Err(e) => ("failed".to_string(), None, Some(e.clone())),
            };

            // Record delivery
            let _ = WebhookDeliveryStore::insert(db, volta_auth_core::record::WebhookDeliveryRecord {
                id: Uuid::new_v4(),
                outbox_event_id: event.id,
                webhook_id: wh.id,
                event_type: event.event_type.clone(),
                status: status.clone(),
                status_code,
                response_body,
                created_at: chrono::Utc::now(),
            }).await;

            if result.is_err() {
                all_ok = false;
            }
        }

        if all_ok || matching.is_empty() {
            OutboxStore::mark_published(db, event.id).await
                .map_err(|e| format!("mark: {}", e))?;
        } else {
            let attempt = event.attempt_count + 1;
            if attempt >= 5 {
                // Give up after 5 attempts
                warn!(event_id = %event.id, "outbox event exceeded max retries, marking published");
                OutboxStore::mark_published(db, event.id).await
                    .map_err(|e| format!("mark: {}", e))?;
            } else {
                OutboxStore::mark_retry(db, event.id, attempt, "delivery failed").await
                    .map_err(|e| format!("retry: {}", e))?;
            }
        }
    }

    Ok(())
}

/// Deliver a webhook: HMAC-signed HTTP POST.
async fn deliver(
    http: &reqwest::Client,
    endpoint_url: &str,
    secret: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<(i32, String), String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let body = serde_json::to_string(payload).unwrap_or_default();

    // HMAC-SHA256 signature (same as Java: sha256(secret + body))
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("hmac: {}", e))?;
    mac.update(body.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let resp = http.post(endpoint_url)
        .header("Content-Type", "application/json")
        .header("X-Volta-Event", event_type)
        .header("X-Volta-Signature", &signature)
        .body(body)
        .send()
        .await
        .map_err(|e| format!("http: {}", e))?;

    let status = resp.status().as_u16() as i32;
    let body = resp.text().await.unwrap_or_default();

    if status >= 200 && status < 300 {
        Ok((status, body))
    } else {
        Err(format!("status {}: {}", status, &body[..body.len().min(200)]))
    }
}
