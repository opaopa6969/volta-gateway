//! volta — unified binary (gateway + auth-core in-process).
//!
//! Phase 0: Uses auth-core for JWT session verification.
//! Gateway falls back to HTTP volta-auth-proxy for full OIDC flows.

fn main() {
    // TODO: Phase 1 — integrate auth-core session verification into gateway
    // For now, just verify the workspace compiles
    println!("volta unified binary — not yet implemented");
    println!("Use `volta-gateway` binary for now.");
    std::process::exit(0);
}
