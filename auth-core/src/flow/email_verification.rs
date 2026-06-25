//! Email verification flow — tramli SM (Phase 1 skeleton; definitions only).
//!
//! TOKEN_ISSUED → SEND_REQUESTED → [external: send outcome] → SENT
//!   → [external: token proof] → VERIFIED. Any error → CANCELLED.
//!
//! token は十分長いランダム値をハッシュ保存（Phase 2）。期限・一度きり・再送
//! rate limit はトークン行の属性として持つ（state には入れない）。

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmailVerificationState {
    TokenIssued,
    SendRequested,
    Sent,
    Verified,
    Cancelled,
}

impl FlowState for EmailVerificationState {
    fn is_terminal(&self) -> bool { matches!(self, Self::Verified | Self::Cancelled) }
    fn is_initial(&self) -> bool { matches!(self, Self::TokenIssued) }
    fn all_states() -> &'static [Self] {
        &[Self::TokenIssued, Self::SendRequested, Self::Sent, Self::Verified, Self::Cancelled]
    }
}

#[derive(Debug, Clone)]
pub struct EmailVerificationInit {
    pub token_id: String,
    pub to: String,
}
#[derive(Debug, Clone)]
pub struct SendRequest {
    pub to: String,
}
/// Injected externally when the notification worker reports a send result.
#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub sent: bool,
}
/// Injected externally when the user submits the verification token.
#[derive(Debug, Clone)]
pub struct VerificationProof {
    pub verified: bool,
}

struct RequestSendProcessor;
impl StateProcessor<EmailVerificationState> for RequestSendProcessor {
    fn name(&self) -> &str { "EvRequestSend" }
    fn requires(&self) -> Vec<TypeId> { requires!(EmailVerificationInit) }
    fn produces(&self) -> Vec<TypeId> { data_types!(SendRequest) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let init = ctx.get::<EmailVerificationInit>()?;
        // Phase 2: enqueue an EMAIL notification job (outbox).
        ctx.put(SendRequest { to: init.to.clone() });
        Ok(())
    }
}

struct MarkSentGuard;
impl TransitionGuard<EmailVerificationState> for MarkSentGuard {
    fn name(&self) -> &str { "EvMarkSentGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(SendOutcome) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<SendOutcome>() {
            Some(o) if o.sent => GuardOutput::accept_with(o.clone()),
            Some(_) => GuardOutput::rejected("send failed"),
            None => GuardOutput::rejected("send not reported"),
        }
    }
}

struct VerifyTokenGuard;
impl TransitionGuard<EmailVerificationState> for VerifyTokenGuard {
    fn name(&self) -> &str { "EvVerifyTokenGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(VerificationProof) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<VerificationProof>() {
            Some(p) if p.verified => GuardOutput::accept_with(p.clone()),
            Some(_) => GuardOutput::rejected("token invalid"),
            None => GuardOutput::rejected("token not submitted"),
        }
    }
}

pub fn build_email_verification_flow() -> Arc<FlowDefinition<EmailVerificationState>> {
    use EmailVerificationState::*;
    Arc::new(
        Builder::new("email_verification")
            .ttl(Duration::from_secs(900))
            .strict_mode()
            .initially_available(requires!(EmailVerificationInit))
            .externally_provided(data_types!(SendOutcome, VerificationProof))
            .from(TokenIssued)
            .auto(SendRequested, RequestSendProcessor)
            .from(SendRequested)
            .external(Sent, MarkSentGuard)
            .from(Sent)
            .external(Verified, VerifyTokenGuard)
            .on_any_error(Cancelled)
            .build()
            .expect("EmailVerification flow definition is invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_and_is_named() {
        assert_eq!(build_email_verification_flow().name, "email_verification");
    }
}
