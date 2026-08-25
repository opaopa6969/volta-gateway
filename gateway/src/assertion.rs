//! Signed gateway-to-backend identity assertion.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TIMESTAMP_HEADER: &str = "x-volta-assertion-timestamp";
pub const SIGNATURE_HEADER: &str = "x-volta-assertion-signature";
pub const MIN_SECRET_LEN: usize = 32;

#[derive(Clone)]
pub struct GatewayAssertionSigner {
    secret: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAssertion {
    pub timestamp: String,
    pub signature: String,
}

impl GatewayAssertionSigner {
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, String> {
        let secret = secret.as_ref();
        if secret.len() < MIN_SECRET_LEN {
            return Err(format!(
                "gateway assertion secret must be at least {MIN_SECRET_LEN} bytes"
            ));
        }
        Ok(Self {
            secret: Arc::from(secret),
        })
    }

    pub fn sign_now(
        &self,
        method: &str,
        path_with_query: &str,
        user_id: &str,
        tenant_id: &str,
        roles: &str,
    ) -> GatewayAssertion {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.sign_at(
            timestamp,
            method,
            path_with_query,
            user_id,
            tenant_id,
            roles,
        )
    }

    pub fn sign_at(
        &self,
        timestamp: u64,
        method: &str,
        path_with_query: &str,
        user_id: &str,
        tenant_id: &str,
        roles: &str,
    ) -> GatewayAssertion {
        let timestamp = timestamp.to_string();
        let canonical = format!(
            "v1\n{timestamp}\n{}\n{path_with_query}\n{user_id}\n{tenant_id}\n{roles}",
            method.to_ascii_uppercase()
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .expect("HMAC accepts arbitrary-length keys");
        mac.update(canonical.as_bytes());
        GatewayAssertion {
            timestamp,
            signature: format!("v1={}", hex::encode(mac.finalize().into_bytes())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_short_secret() {
        assert!(GatewayAssertionSigner::new("too-short").is_err());
    }

    #[test]
    fn signs_the_cross_service_canonical_form() {
        let signer = GatewayAssertionSigner::new("0123456789abcdef0123456789abcdef").unwrap();
        let assertion = signer.sign_at(
            1_700_000_000,
            "get",
            "/v1/items?q=1",
            "user-1",
            "tenant-1",
            "ADMIN,MEMBER",
        );
        assert_eq!(assertion.timestamp, "1700000000");
        assert_eq!(
            assertion.signature,
            "v1=bb4fb0ab85dbaf12f10b29e2fe436b2d5eeb6d836c40255fed4a9fd41cd5f568"
        );
    }
}
