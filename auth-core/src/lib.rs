//! volta-auth-core — Auth library crate.
//!
//! Phase 0-5 complete. SAML → Java sidecar (DD-005).

pub mod jwt;
pub mod session;
pub mod error;
pub mod record;
pub mod store;
pub mod policy;
pub mod token;
pub mod flow;
pub mod idp;
pub mod totp;
pub mod service;
pub mod crypto;
#[cfg(feature = "webauthn")]
pub mod passkey;
