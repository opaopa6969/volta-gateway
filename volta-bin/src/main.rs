//! volta — unified binary (gateway + auth-core in-process).
//!
//! Single binary that runs:
//! - HTTP reverse proxy (volta-gateway)
//! - In-process JWT auth verification (volta-auth-core)
//! - All tramli SM flows (OIDC, MFA, Passkey, Invite)
//!
//! Usage: volta config.yaml
//!        volta --validate config.yaml

use tramli::FlowState;
use volta_auth_core::{jwt::JwtVerifier, session::SessionVerifier, policy::PolicyEngine};
use volta_auth_core::flow::{oidc, mfa, passkey, invite};

fn main() {
    println!("volta unified binary v0.1.0");
    println!();

    // Verify auth-core components are available
    let verifier = JwtVerifier::new_hs256(b"placeholder-secret-for-startup-check!!");
    let _session = SessionVerifier::new(verifier, "__volta_session");
    let policy = PolicyEngine::default_policy();

    println!("Auth components:");
    println!("  JWT verifier:     HS256 ready");
    println!("  Session verifier: cookie-based");
    println!("  Policy engine:    {} roles", policy.hierarchy().len());

    // Verify all tramli SM flows build successfully
    let _oidc = oidc::build_oidc_flow();
    let _mfa = mfa::build_mfa_flow();
    let _passkey = passkey::build_passkey_flow();
    let _invite = invite::build_invite_flow();
    let _token = volta_auth_core::token::build_token_flow();

    println!("  OIDC flow:        ✓ ({} states)", oidc::OidcState::all_states().len());
    println!("  MFA flow:         ✓ ({} states)", mfa::MfaState::all_states().len());
    println!("  Passkey flow:     ✓ ({} states)", passkey::PasskeyState::all_states().len());
    println!("  Invite flow:      ✓ ({} states)", invite::InviteState::all_states().len());
    println!("  Token flow:       ✓");
    println!();

    // Forward to gateway
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: volta <config.yaml>");
        println!("       volta --validate <config.yaml>");
        println!();
        println!("This binary includes volta-gateway + volta-auth-core.");
        println!("All auth flows run in-process (no HTTP roundtrip).");
        std::process::exit(0);
    }

    println!("Starting volta-gateway with in-process auth...");
    println!("(Full integration pending — use `volta-gateway` binary for now)");

    // TODO: Launch gateway with auth-core wired in
    // The plumbing is: gateway's VoltaAuthClient checks auth-core first,
    // falls back to HTTP volta-auth-proxy for flows not yet in Rust.
}
