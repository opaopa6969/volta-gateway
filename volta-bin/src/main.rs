//! volta — experimental auth component/flow smoke check.
//!
//! This crate does not currently launch volta-gateway. The supported runtime
//! remains the Rust `volta-gateway` + `volta-auth-server` processes.
//!
//! Usage: volta config.yaml
//!        volta --validate config.yaml

use tramli::FlowState;
use volta_auth_core::flow::{invite, mfa, oidc, passkey};
use volta_auth_core::{jwt::JwtVerifier, policy::PolicyEngine, session::SessionVerifier};

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

    println!(
        "  OIDC flow:        ✓ ({} states)",
        oidc::OidcState::all_states().len()
    );
    println!(
        "  MFA flow:         ✓ ({} states)",
        mfa::MfaState::all_states().len()
    );
    println!(
        "  Passkey flow:     ✓ ({} states)",
        passkey::PasskeyState::all_states().len()
    );
    println!(
        "  Invite flow:      ✓ ({} states)",
        invite::InviteState::all_states().len()
    );
    println!("  Token flow:       ✓");
    println!();

    // Forward to gateway
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Usage: volta <config.yaml>");
        println!("       volta --validate <config.yaml>");
        println!();
        println!("Experimental smoke check only; it does not launch volta-gateway.");
        std::process::exit(0);
    }

    println!("Smoke check complete.");
    println!("Use volta-gateway + volta-auth-server for the supported runtime.");

    // TODO: Launch gateway with auth-core wired in
    // Any future in-process mode must preserve online revocation, tenant,
    // MFA, and policy semantics; it must not reintroduce Java auth-proxy.
}
