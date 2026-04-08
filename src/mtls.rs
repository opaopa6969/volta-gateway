//! #9: mTLS connector for backend connections.
//!
//! Builds a hyper client with mutual TLS (client certificate + CA verification).

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use std::sync::Arc;

/// Per-route backend TLS configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BackendTlsConfig {
    /// CA certificate for verifying backend server
    pub ca_cert: String,
    /// Client certificate for mutual TLS
    pub client_cert: String,
    /// Client private key
    pub client_key: String,
}

/// Build a rustls ClientConfig for mTLS.
pub fn build_mtls_config(config: &BackendTlsConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    // Load CA cert
    let ca_data = std::fs::read(&config.ca_cert)
        .map_err(|e| format!("failed to read CA cert {}: {}", config.ca_cert, e))?;
    let mut ca_reader = std::io::BufReader::new(ca_data.as_slice());
    let ca_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut ca_reader)
        .filter_map(|r| r.ok())
        .collect();

    let mut root_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        root_store.add(cert).map_err(|e| format!("invalid CA cert: {}", e))?;
    }

    // Load client cert chain
    let cert_data = std::fs::read(&config.client_cert)
        .map_err(|e| format!("failed to read client cert {}: {}", config.client_cert, e))?;
    let mut cert_reader = std::io::BufReader::new(cert_data.as_slice());
    let client_certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|r| r.ok())
        .collect();

    // Load client key
    let key_data = std::fs::read(&config.client_key)
        .map_err(|e| format!("failed to read client key {}: {}", config.client_key, e))?;
    let mut key_reader = std::io::BufReader::new(key_data.as_slice());
    let client_key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("failed to parse client key: {}", e))?
        .ok_or_else(|| "no private key found in file".to_string())?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)
        .map_err(|e| format!("mTLS config error: {}", e))?;

    Ok(Arc::new(config))
}

/// Build a hyper-rustls HTTPS connector with mTLS.
pub fn build_mtls_connector(
    tls_config: Arc<rustls::ClientConfig>,
) -> hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config((*tls_config).clone())
        .https_or_http()
        .enable_http1()
        .build()
}
