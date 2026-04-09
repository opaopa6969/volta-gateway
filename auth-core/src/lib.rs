//! volta-auth-core — Auth library crate.
//!
//! Phase 0: ✅ JWT session verification
//! Phase 1: ✅ Session store, policy engine
//! Phase 1.5: ✅ Token refresh (tramli SM)
//! Phase 2: ✅ OIDC flow (tramli SM)
//! Phase 2.5: ✅ MFA flow (tramli SM)
//! Phase 3: ✅ Passkey flow (tramli SM)
//! Phase 3.5: ✅ Invite flow (tramli SM)

pub mod jwt;
pub mod session;
pub mod error;
pub mod record;
pub mod store;
pub mod policy;
pub mod token;
pub mod flow;
