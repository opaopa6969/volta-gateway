//! Auth flows — tramli SM definitions for OIDC, MFA, Passkey, Invite.
//! 1:1 port from Java volta-auth-proxy.

pub mod oidc;
pub mod registration;
pub mod email_verification;
pub mod password_reset;
pub mod mfa_setup;
pub mod login_challenge;
pub mod mfa;
pub mod passkey;
pub mod invite;
pub mod mermaid;
pub mod validate;
