//! Signed gateway-to-backend identity assertion.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TIMESTAMP_HEADER: &str = "x-volta-assertion-timestamp";
pub const SIGNATURE_HEADER: &str = "x-volta-assertion-signature";
pub const KEY_ID_HEADER: &str = "x-volta-assertion-key-id";
pub const MIN_SECRET_LEN: usize = 32;
pub const LEGACY_KEY_ID: &str = "legacy";

#[derive(Clone)]
pub struct GatewayAssertionSigner {
    key_id: Arc<str>,
    secret: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAssertion {
    pub key_id: String,
    pub timestamp: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct GatewayAssertionVerifier {
    current: GatewayAssertionSigner,
    previous: Option<GatewayAssertionSigner>,
}

impl GatewayAssertionSigner {
    pub fn new(secret: impl AsRef<[u8]>) -> Result<Self, String> {
        Self::new_with_key_id(LEGACY_KEY_ID, secret)
    }

    pub fn new_with_key_id(
        key_id: impl AsRef<str>,
        secret: impl AsRef<[u8]>,
    ) -> Result<Self, String> {
        let key_id = key_id.as_ref();
        validate_key_id(key_id)?;
        let secret = secret.as_ref();
        if secret.len() < MIN_SECRET_LEN {
            return Err(format!(
                "gateway assertion secret must be at least {MIN_SECRET_LEN} bytes"
            ));
        }
        Ok(Self {
            key_id: Arc::from(key_id),
            secret: Arc::from(secret),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
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
            key_id: self.key_id.to_string(),
            timestamp,
            signature: format!("v1={}", hex::encode(mac.finalize().into_bytes())),
        }
    }
}

impl GatewayAssertionVerifier {
    pub fn new(
        current: GatewayAssertionSigner,
        previous: Option<GatewayAssertionSigner>,
    ) -> Result<Self, String> {
        if previous
            .as_ref()
            .is_some_and(|previous| previous.key_id() == current.key_id())
        {
            return Err("current and previous assertion key IDs must differ".into());
        }
        Ok(Self { current, previous })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify_at(
        &self,
        key_id: Option<&str>,
        timestamp: &str,
        signature: &str,
        now: u64,
        max_clock_skew_secs: u64,
        method: &str,
        path_with_query: &str,
        user_id: &str,
        tenant_id: &str,
        roles: &str,
    ) -> Result<(), String> {
        let timestamp_u64 = timestamp
            .parse::<u64>()
            .map_err(|_| "invalid assertion timestamp".to_string())?;
        if now.abs_diff(timestamp_u64) > max_clock_skew_secs {
            return Err("assertion timestamp outside replay window".into());
        }
        let signer = match key_id {
            Some(key_id) if key_id == self.current.key_id() => &self.current,
            Some(key_id) => self
                .previous
                .as_ref()
                .filter(|previous| previous.key_id() == key_id)
                .ok_or_else(|| "unknown assertion key ID".to_string())?,
            None if self.previous.is_none() => &self.current,
            None => return Err("assertion key ID required while rotating keys".into()),
        };
        let provided = signature
            .strip_prefix("v1=")
            .ok_or_else(|| "unsupported assertion signature version".to_string())?;
        let provided = hex::decode(provided)
            .map_err(|_| "invalid assertion signature encoding".to_string())?;
        let canonical = format!(
            "v1\n{timestamp}\n{}\n{path_with_query}\n{user_id}\n{tenant_id}\n{roles}",
            method.to_ascii_uppercase()
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(&signer.secret)
            .expect("HMAC accepts arbitrary-length keys");
        mac.update(canonical.as_bytes());
        mac.verify_slice(&provided)
            .map_err(|_| "invalid assertion signature".to_string())
    }
}

pub fn validate_key_id(key_id: &str) -> Result<(), String> {
    if key_id.is_empty()
        || key_id.len() > 64
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("assertion key ID must be 1-64 ASCII letters, digits, '.', '_' or '-'".into());
    }
    Ok(())
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
        assert_eq!(assertion.key_id, LEGACY_KEY_ID);
        assert_eq!(
            assertion.signature,
            "v1=bb4fb0ab85dbaf12f10b29e2fe436b2d5eeb6d836c40255fed4a9fd41cd5f568"
        );
    }

    #[test]
    fn verifier_accepts_current_and_previous_during_rotation() {
        let current = GatewayAssertionSigner::new_with_key_id(
            "2026-09",
            "current-current-current-current-12",
        )
        .unwrap();
        let previous = GatewayAssertionSigner::new_with_key_id(
            "2026-08",
            "previous-previous-previous-prev12",
        )
        .unwrap();
        let verifier = GatewayAssertionVerifier::new(current.clone(), Some(previous.clone())).unwrap();
        for signer in [current, previous] {
            let assertion = signer.sign_at(1_700_000_000, "POST", "/billing", "u", "t", "ADMIN");
            verifier
                .verify_at(
                    Some(&assertion.key_id),
                    &assertion.timestamp,
                    &assertion.signature,
                    1_700_000_010,
                    30,
                    "POST",
                    "/billing",
                    "u",
                    "t",
                    "ADMIN",
                )
                .unwrap();
        }
    }

    #[test]
    fn verifier_fails_closed_for_unknown_or_missing_key_id_during_rotation() {
        let current = GatewayAssertionSigner::new_with_key_id(
            "current",
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let previous = GatewayAssertionSigner::new_with_key_id(
            "previous",
            "abcdef0123456789abcdef0123456789",
        )
        .unwrap();
        let assertion = current.sign_at(100, "GET", "/", "", "", "");
        let verifier = GatewayAssertionVerifier::new(current, Some(previous)).unwrap();
        for key_id in [None, Some("unknown")] {
            assert!(verifier
                .verify_at(
                    key_id,
                    &assertion.timestamp,
                    &assertion.signature,
                    100,
                    10,
                    "GET",
                    "/",
                    "",
                    "",
                    "",
                )
                .is_err());
        }
    }
}
