//! Registration flow — tramli SM (Phase 1 skeleton; definitions only).
//!
//! Start → EMAIL_VERIFICATION_PENDING → [external: verified] → EMAIL_VERIFIED
//!   → [branch: MFA setup | skip] → (MFA_SETUP_OPTIONAL → [external: done] →) COMPLETED
//! Any error → CANCELLED.
//!
//! Config gating (email-verification on/off, MFA required/optional/disabled) is
//! applied at runtime by *which* transitions are driven; the static graph
//! carries the full lifecycle. Real side-effects (issue/hash token, enqueue
//! notification, persist) land in Phase 2.

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistrationState {
    Start,
    EmailVerificationPending,
    EmailVerified,
    MfaSetupOptional,
    Completed,
    Cancelled,
}

impl FlowState for RegistrationState {
    fn is_terminal(&self) -> bool { matches!(self, Self::Completed | Self::Cancelled) }
    fn is_initial(&self) -> bool { matches!(self, Self::Start) }
    fn all_states() -> &'static [Self] {
        &[
            Self::Start,
            Self::EmailVerificationPending,
            Self::EmailVerified,
            Self::MfaSetupOptional,
            Self::Completed,
            Self::Cancelled,
        ]
    }
}

// ── flow data ───────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct RegistrationInit {
    pub email: String,
    pub correlation_id: String,
}
#[derive(Debug, Clone)]
pub struct VerificationIssued {
    pub token_id: String,
}
/// Injected externally when the user proves email ownership.
#[derive(Debug, Clone)]
pub struct EmailVerifiedData {
    pub email: String,
}
/// Runtime hint for the MFA branch: "setup" | "skip" (driven by config/user).
#[derive(Debug, Clone)]
pub struct MfaChoice {
    pub label: String,
}
/// Injected externally when the MFA setup sub-step completes.
#[derive(Debug, Clone)]
pub struct MfaSetupResult {
    pub enabled: bool,
}

// ── processors / guards / branch ────────────────────────
struct IssueVerificationProcessor;
impl StateProcessor<RegistrationState> for IssueVerificationProcessor {
    fn name(&self) -> &str { "RegIssueVerification" }
    fn requires(&self) -> Vec<TypeId> { requires!(RegistrationInit) }
    fn produces(&self) -> Vec<TypeId> { data_types!(VerificationIssued) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let init = ctx.get::<RegistrationInit>()?;
        // Phase 2: issue a hashed token row + enqueue an EMAIL notification job.
        ctx.put(VerificationIssued { token_id: format!("pending:{}", init.correlation_id) });
        Ok(())
    }
}

struct VerifyEmailGuard;
impl TransitionGuard<RegistrationState> for VerifyEmailGuard {
    fn name(&self) -> &str { "RegVerifyEmailGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(EmailVerifiedData) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<EmailVerifiedData>() {
            Some(d) => GuardOutput::accept_with(d.clone()),
            None => GuardOutput::rejected("email not yet verified"),
        }
    }
}

struct MfaBranch;
impl BranchProcessor<RegistrationState> for MfaBranch {
    fn name(&self) -> &str { "RegMfaBranch" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn decide(&self, ctx: &FlowContext) -> String {
        ctx.find::<MfaChoice>()
            .map(|c| c.label.clone())
            .unwrap_or_else(|| "skip".to_string())
    }
}

struct MfaDoneGuard;
impl TransitionGuard<RegistrationState> for MfaDoneGuard {
    fn name(&self) -> &str { "RegMfaDoneGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(MfaSetupResult) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<MfaSetupResult>() {
            Some(d) => GuardOutput::accept_with(d.clone()),
            None => GuardOutput::rejected("mfa setup not completed"),
        }
    }
}

pub fn build_registration_flow() -> Arc<FlowDefinition<RegistrationState>> {
    use RegistrationState::*;
    Arc::new(
        Builder::new("registration")
            .ttl(Duration::from_secs(3600))
            .strict_mode()
            .initially_available(requires!(RegistrationInit))
            .externally_provided(data_types!(EmailVerifiedData, MfaSetupResult, MfaChoice))
            .from(Start)
            .auto(EmailVerificationPending, IssueVerificationProcessor)
            .from(EmailVerificationPending)
            .external(EmailVerified, VerifyEmailGuard)
            .from(EmailVerified)
            .branch(MfaBranch)
            .to(MfaSetupOptional, "setup")
            .to(Completed, "skip")
            .end_branch()
            .from(MfaSetupOptional)
            .external(Completed, MfaDoneGuard)
            .on_any_error(Cancelled)
            .build()
            .expect("Registration flow definition is invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_is_named() {
        let def = build_registration_flow();
        assert_eq!(def.name, "registration");
    }
}
