//! DNS-01 ACME challenge support — DNS TXT record management + full ACME flow.
//!
//! Phase 1: Cloudflare DNS provider (TXT record CRUD).
//! Phase 2: Full ACME DNS-01 order flow via `instant-acme`.

use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};

use crate::config::TlsConfig;

/// DNS-01 provider trait — create/delete TXT records for ACME challenges.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create a TXT record at `_acme-challenge.{domain}` with the given value.
    /// Returns the record ID for cleanup.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String, String>;

    /// Delete a previously created TXT record by ID.
    async fn delete_txt_record(&self, record_id: &str) -> Result<(), String>;
}

/// Create the appropriate DNS provider from TLS config.
pub fn create_provider(tls: &TlsConfig) -> Option<Box<dyn DnsProvider>> {
    let provider = tls.dns_provider.as_deref()?;

    match provider {
        "cloudflare" => {
            let api_token = tls.dns_api_token.clone()
                .or_else(|| std::env::var("CF_DNS_API_TOKEN").ok())
                .unwrap_or_default();
            let zone_id = tls.dns_zone_id.clone()
                .or_else(|| std::env::var("CF_ZONE_ID").ok())
                .unwrap_or_default();

            if api_token.is_empty() || zone_id.is_empty() {
                error!("Cloudflare DNS-01: dns_api_token and dns_zone_id are required");
                return None;
            }

            Some(Box::new(CloudflareDns::new(&api_token, &zone_id)))
        }
        _ => {
            error!(provider = provider, "unsupported DNS provider");
            None
        }
    }
}

// ─── Cloudflare Provider ──────────────────────────────────

/// Cloudflare DNS record manager for ACME DNS-01 challenges.
pub struct CloudflareDns {
    api_token: String,
    zone_id: String,
    http: reqwest::Client,
}

impl CloudflareDns {
    pub fn new(api_token: &str, zone_id: &str) -> Self {
        Self {
            api_token: api_token.to_string(),
            zone_id: zone_id.to_string(),
            http: reqwest::Client::new(),
        }
    }

    fn api_url(&self, path: &str) -> String {
        format!("https://api.cloudflare.com/client/v4/zones/{}{}", self.zone_id, path)
    }
}

#[derive(Serialize)]
struct CfCreateRecord {
    #[serde(rename = "type")]
    record_type: String,
    name: String,
    content: String,
    ttl: u32,
}

#[derive(Deserialize)]
struct CfResponse {
    success: bool,
    result: Option<CfResult>,
    errors: Vec<CfError>,
}

#[derive(Deserialize)]
struct CfResult {
    id: String,
}

#[derive(Deserialize)]
struct CfError {
    message: String,
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareDns {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String, String> {
        let acme_domain = format!("_acme-challenge.{}", domain.trim_start_matches("*."));
        info!(domain = %acme_domain, "creating DNS-01 TXT record");

        let body = CfCreateRecord {
            record_type: "TXT".into(),
            name: acme_domain,
            content: value.to_string(),
            ttl: 120,
        };

        let resp = self.http.post(&self.api_url("/dns_records"))
            .bearer_auth(&self.api_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("cloudflare API: {}", e))?;

        let status = resp.status();
        let cf: CfResponse = resp.json().await
            .map_err(|e| format!("cloudflare parse: {}", e))?;

        if !cf.success {
            let errors: Vec<String> = cf.errors.iter().map(|e| e.message.clone()).collect();
            return Err(format!("cloudflare error ({}): {}", status, errors.join(", ")));
        }

        let record_id = cf.result
            .ok_or("cloudflare: no result in response")?
            .id;

        info!(record_id = %record_id, "DNS-01 TXT record created");
        Ok(record_id)
    }

    async fn delete_txt_record(&self, record_id: &str) -> Result<(), String> {
        info!(record_id = %record_id, "deleting DNS-01 TXT record");

        let resp = self.http.delete(&self.api_url(&format!("/dns_records/{}", record_id)))
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| format!("cloudflare API: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("cloudflare delete: {}", resp.status()));
        }

        info!(record_id = %record_id, "DNS-01 TXT record deleted");
        Ok(())
    }
}

// ─── ACME DNS-01 Full Flow ────────────────────────────────

/// Obtain a certificate via ACME DNS-01 challenge using `instant-acme`.
///
/// Flow:
///   1. Create ACME account
///   2. Create order for domains
///   3. For each authorization, create DNS TXT record via provider
///   4. Notify ACME server that challenge is ready
///   5. Poll until order is ready
///   6. Finalize order (CSR generated internally by instant-acme + rcgen)
///   7. Download certificate
///   8. Cleanup DNS records
pub async fn obtain_certificate_dns01(
    tls_config: &TlsConfig,
    provider: &dyn DnsProvider,
) -> Result<AcmeCertificate, String> {
    use instant_acme::{
        Account, NewAccount, NewOrder, OrderStatus, ChallengeType, RetryPolicy,
    };

    let directory_url = if tls_config.staging {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-v02.api.letsencrypt.org/directory"
    };

    info!(directory = directory_url, domains = ?tls_config.domains, "starting ACME DNS-01 flow");

    // 1. Create account
    let contact = format!("mailto:{}", tls_config.contact_email);
    let (account, _credentials) = Account::builder()
        .map_err(|e| format!("ACME builder: {}", e))?
        .create(
            &NewAccount {
                contact: &[&contact],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url.to_string(),
            None,
        )
        .await
        .map_err(|e| format!("ACME account: {}", e))?;

    info!("ACME account created");

    // 2. Create order
    let identifiers: Vec<instant_acme::Identifier> = tls_config.domains.iter()
        .map(|d| instant_acme::Identifier::Dns(d.clone()))
        .collect();

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("ACME order: {}", e))?;

    info!("ACME order created");

    // 3. Process authorizations — create DNS TXT records
    let mut dns_records: Vec<(String, String)> = Vec::new();
    let mut authorizations = order.authorizations();

    while let Some(auth_result) = authorizations.next().await {
        let mut auth = auth_result.map_err(|e| format!("ACME auth: {}", e))?;

        let mut challenge = auth.challenge(ChallengeType::Dns01)
            .ok_or_else(|| "no DNS-01 challenge offered".to_string())?;

        let key_auth = challenge.key_authorization();
        let dns_value = key_auth.dns_value();
        let domain = challenge.identifier().to_string();

        // Create TXT record via DNS provider
        let record_id = provider.create_txt_record(&domain, &dns_value).await?;
        dns_records.push((domain.clone(), record_id));

        // Wait for DNS propagation
        info!(domain = %domain, "waiting for DNS propagation (10s)");
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        // 4. Tell ACME server the challenge is ready
        challenge.set_ready().await
            .map_err(|e| format!("ACME set_ready: {}", e))?;

        info!(domain = %domain, "DNS-01 challenge submitted");
    }
    drop(authorizations);

    // 5. Poll until order is ready
    let retry = RetryPolicy::default();
    order.poll_ready(&retry).await
        .map_err(|e| {
            // Fire-and-forget cleanup
            let records = dns_records.clone();
            tokio::spawn(async move {
                // Can't use provider here (not Send), but log for manual cleanup
                warn!(records = ?records, "ACME failed — DNS records may need manual cleanup");
            });
            format!("ACME poll_ready: {}", e)
        })?;

    info!("ACME order ready — finalizing");

    // 6. Finalize (generates CSR internally via rcgen)
    let private_key_pem = order.finalize().await
        .map_err(|e| format!("ACME finalize: {}", e))?;

    // 7. Download certificate
    let cert_chain_pem = order.poll_certificate(&retry).await
        .map_err(|e| format!("ACME certificate: {}", e))?;

    // 8. Cleanup DNS records
    cleanup_dns_records(provider, &dns_records).await;

    info!(domains = ?tls_config.domains, "ACME DNS-01 certificate obtained");

    Ok(AcmeCertificate {
        cert_chain_pem,
        private_key_pem,
    })
}

async fn cleanup_dns_records(provider: &dyn DnsProvider, records: &[(String, String)]) {
    for (domain, record_id) in records {
        if let Err(e) = provider.delete_txt_record(record_id).await {
            warn!(domain = %domain, error = %e, "failed to cleanup DNS record");
        }
    }
}

/// Certificate obtained via ACME.
pub struct AcmeCertificate {
    pub cert_chain_pem: String,
    pub private_key_pem: String,
}
