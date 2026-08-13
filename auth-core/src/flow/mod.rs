//! Auth flows — tramli SM definitions for OIDC, MFA, Passkey, Invite.
//! 1:1 port from Java volta-auth-proxy.

pub mod device_grant;
pub mod email_verification;
pub mod invite;
pub mod login_challenge;
pub mod mermaid;
pub mod mfa;
pub mod mfa_setup;
pub mod oidc;
pub mod passkey;
pub mod password_reset;
pub mod registration;
pub mod validate;
