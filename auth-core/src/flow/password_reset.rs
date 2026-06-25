//! Password reset flow — tramli SM (Phase 1 skeleton; definitions only).
//!
//! REQUESTED → TOKEN_ISSUED → SEND_REQUESTED → [external: sent] → SENT
//!   → [external: token verified] → TOKEN_VERIFIED → [external: changed]
//!   → PASSWORD_CHANGED → COMPLETED. Any error → CANCELLED.
//!
//! account enumeration を避けるため、存在しないメールでも REQUESTED→…→SENT を
//! 同様に通し外部応答を一定にする（実送信は実在時のみ。Phase 3）。token は
//! ハッシュ保存・期限・一度きり・試行/再送制限を属性で持つ。
//! password 能力自体は `AUTH_PASSWORD_ENABLED` 設定で gate（未決事項§7-1）。

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordResetState {
    Requested,
    TokenIssued,
    SendRequested,
    Sent,
    TokenVerified,
    PasswordChanged,
    Completed,
    Cancelled,
}

impl FlowState for PasswordResetState {
    fn is_terminal(&self) -> bool { matches!(self, Self::Completed | Self::Cancelled) }
    fn is_initial(&self) -> bool { matches!(self, Self::Requested) }
    fn all_states() -> &'static [Self] {
        &[
            Self::Requested, Self::TokenIssued, Self::SendRequested, Self::Sent,
            Self::TokenVerified, Self::PasswordChanged, Self::Completed, Self::Cancelled,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct PasswordResetInit {
    pub email: String,
    pub correlation_id: String,
}
#[derive(Debug, Clone)]
pub struct ResetTokenIssued {
    pub token_id: String,
}
#[derive(Debug, Clone)]
pub struct ResetSendRequest {
    pub to: String,
}
/// Externally injected by the notification worker.
#[derive(Debug, Clone)]
pub struct ResetSendOutcome {
    pub sent: bool,
}
/// Externally injected when the user submits the reset token.
#[derive(Debug, Clone)]
pub struct ResetTokenProof {
    pub valid: bool,
}
/// Externally injected after the new password is accepted.
#[derive(Debug, Clone)]
pub struct PasswordChangedData {
    pub changed: bool,
}

struct IssueResetTokenProcessor;
impl StateProcessor<PasswordResetState> for IssueResetTokenProcessor {
    fn name(&self) -> &str { "PrIssueResetToken" }
    fn requires(&self) -> Vec<TypeId> { requires!(PasswordResetInit) }
    fn produces(&self) -> Vec<TypeId> { data_types!(ResetTokenIssued) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let init = ctx.get::<PasswordResetInit>()?;
        // Phase 3: issue a hashed reset token row (only if the account exists,
        // but the flow path is identical to avoid enumeration).
        ctx.put(ResetTokenIssued { token_id: format!("pending:{}", init.correlation_id) });
        Ok(())
    }
}

struct ResetRequestSendProcessor;
impl StateProcessor<PasswordResetState> for ResetRequestSendProcessor {
    fn name(&self) -> &str { "PrRequestSend" }
    fn requires(&self) -> Vec<TypeId> { requires!(ResetTokenIssued, PasswordResetInit) }
    fn produces(&self) -> Vec<TypeId> { data_types!(ResetSendRequest) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let init = ctx.get::<PasswordResetInit>()?;
        ctx.put(ResetSendRequest { to: init.email.clone() });
        Ok(())
    }
}

struct ResetMarkSentGuard;
impl TransitionGuard<PasswordResetState> for ResetMarkSentGuard {
    fn name(&self) -> &str { "PrMarkSentGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(ResetSendOutcome) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<ResetSendOutcome>() {
            Some(o) => GuardOutput::accept_with(o.clone()),
            None => GuardOutput::rejected("send not reported"),
        }
    }
}

struct VerifyResetTokenGuard;
impl TransitionGuard<PasswordResetState> for VerifyResetTokenGuard {
    fn name(&self) -> &str { "PrVerifyResetTokenGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(ResetTokenProof) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<ResetTokenProof>() {
            Some(p) if p.valid => GuardOutput::accept_with(p.clone()),
            Some(_) => GuardOutput::rejected("reset token invalid"),
            None => GuardOutput::rejected("reset token not submitted"),
        }
    }
}

struct ChangePasswordGuard;
impl TransitionGuard<PasswordResetState> for ChangePasswordGuard {
    fn name(&self) -> &str { "PrChangePasswordGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(PasswordChangedData) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<PasswordChangedData>() {
            Some(d) if d.changed => GuardOutput::accept_with(d.clone()),
            Some(_) => GuardOutput::rejected("password not changed"),
            None => GuardOutput::rejected("new password not submitted"),
        }
    }
}

struct CompleteResetProcessor;
impl StateProcessor<PasswordResetState> for CompleteResetProcessor {
    fn name(&self) -> &str { "PrComplete" }
    fn requires(&self) -> Vec<TypeId> { requires!(PasswordChangedData) }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _ = ctx.get::<PasswordChangedData>()?;
        // Phase 3: optionally invalidate existing sessions (config/TODO).
        Ok(())
    }
}

pub fn build_password_reset_flow() -> Arc<FlowDefinition<PasswordResetState>> {
    use PasswordResetState::*;
    Arc::new(
        Builder::new("password_reset")
            .ttl(Duration::from_secs(900))
            .strict_mode()
            .initially_available(requires!(PasswordResetInit))
            .externally_provided(data_types!(ResetSendOutcome, ResetTokenProof, PasswordChangedData))
            .from(Requested)
            .auto(TokenIssued, IssueResetTokenProcessor)
            .from(TokenIssued)
            .auto(SendRequested, ResetRequestSendProcessor)
            .from(SendRequested)
            .external(Sent, ResetMarkSentGuard)
            .from(Sent)
            .external(TokenVerified, VerifyResetTokenGuard)
            .from(TokenVerified)
            .external(PasswordChanged, ChangePasswordGuard)
            .from(PasswordChanged)
            .auto(Completed, CompleteResetProcessor)
            .on_any_error(Cancelled)
            .build()
            .expect("PasswordReset flow definition is invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_and_is_named() {
        assert_eq!(build_password_reset_flow().name, "password_reset");
    }
}
