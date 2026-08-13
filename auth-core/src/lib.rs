//! volta-auth-core — Auth library crate.
//!
//! Phase 0-5 complete. SAML → Java sidecar (DD-005).

pub mod crypto;
pub mod dpop;
pub mod error;
pub mod flow;
pub mod idp;
pub mod jwks;
pub mod jwt;
pub mod notification;
pub mod oidc;
#[cfg(feature = "webauthn")]
pub mod passkey;
pub mod policy;
pub mod record;
pub mod risk;
pub mod runtime;
pub mod service;
pub mod session;
pub mod store;
pub mod token;
pub mod totp;
