//! volta-auth-core — Auth library crate.
//!
//! Phase 0: ✅ JWT session verification (jwt.rs, session.rs)
//! Phase 1: ✅ Session store, policy engine (store.rs, policy.rs, record.rs, error.rs)
//! Phase 2: OIDC, MFA, Passkey flows (tramli SM)

pub mod jwt;
pub mod session;
pub mod error;
pub mod record;
pub mod store;
pub mod policy;
