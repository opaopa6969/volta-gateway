//! Login challenge flow — tramli SM (Phase 1 skeleton; definitions only).
//!
//! PASSWORD_ACCEPTED → [branch: MFA required | grant] → MFA_REQUIRED
//!   → CHALLENGE_SENT → [external: verified] → CHALLENGE_VERIFIED → LOGIN_GRANTED.
//! Any error → LOGIN_DENIED.
//!
//! MFA 有効ユーザーは MFA_REQUIRED を通る。`AUTH_MFA_LOGIN=disabled` や非対象
//! ユーザーは "grant" 分岐で直接 LOGIN_GRANTED。Email/SMS/LINE OTP は通知設定に
//! 応じて challenge 送信先を変える（TOTP は外部送信なし）。試行/期限/再送は属性。

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoginChallengeState {
    PasswordAccepted,
    MfaRequired,
    ChallengeSent,
    ChallengeVerified,
    LoginGranted,
    LoginDenied,
}

impl FlowState for LoginChallengeState {
    fn is_terminal(&self) -> bool { matches!(self, Self::LoginGranted | Self::LoginDenied) }
    fn is_initial(&self) -> bool { matches!(self, Self::PasswordAccepted) }
    fn all_states() -> &'static [Self] {
        &[
            Self::PasswordAccepted, Self::MfaRequired, Self::ChallengeSent,
            Self::ChallengeVerified, Self::LoginGranted, Self::LoginDenied,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct LoginChallengeInit {
    pub user_id: String,
    /// Resolved from config + user MFA state by the caller.
    pub mfa_required: bool,
    /// "TOTP" | "EMAIL_OTP" | "SMS_OTP" | "LINE_OTP"
    pub method: String,
}
#[derive(Debug, Clone)]
pub struct ChallengeSentData {
    pub method: String,
}
/// Externally injected when the user submits the challenge response.
#[derive(Debug, Clone)]
pub struct ChallengeProof {
    pub verified: bool,
}

struct MfaRequiredBranch;
impl BranchProcessor<LoginChallengeState> for MfaRequiredBranch {
    fn name(&self) -> &str { "LcMfaRequiredBranch" }
    fn requires(&self) -> Vec<TypeId> { requires!(LoginChallengeInit) }
    fn decide(&self, ctx: &FlowContext) -> String {
        match ctx.find::<LoginChallengeInit>() {
            Some(i) if i.mfa_required => "mfa".to_string(),
            _ => "grant".to_string(),
        }
    }
}

struct SendChallengeProcessor;
impl StateProcessor<LoginChallengeState> for SendChallengeProcessor {
    fn name(&self) -> &str { "LcSendChallenge" }
    fn requires(&self) -> Vec<TypeId> { requires!(LoginChallengeInit) }
    fn produces(&self) -> Vec<TypeId> { data_types!(ChallengeSentData) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let init = ctx.get::<LoginChallengeInit>()?;
        // Phase 5: for EMAIL/SMS/LINE OTP enqueue a notification; TOTP sends nothing.
        ctx.put(ChallengeSentData { method: init.method.clone() });
        Ok(())
    }
}

struct VerifyChallengeGuard;
impl TransitionGuard<LoginChallengeState> for VerifyChallengeGuard {
    fn name(&self) -> &str { "LcVerifyChallengeGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(ChallengeProof) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<ChallengeProof>() {
            Some(p) if p.verified => GuardOutput::accept_with(p.clone()),
            Some(_) => GuardOutput::rejected("challenge response invalid"),
            None => GuardOutput::rejected("challenge response not submitted"),
        }
    }
}

struct GrantProcessor;
impl StateProcessor<LoginChallengeState> for GrantProcessor {
    fn name(&self) -> &str { "LcGrant" }
    fn requires(&self) -> Vec<TypeId> { requires!(ChallengeProof) }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _ = ctx.get::<ChallengeProof>()?;
        Ok(())
    }
}

pub fn build_login_challenge_flow() -> Arc<FlowDefinition<LoginChallengeState>> {
    use LoginChallengeState::*;
    Arc::new(
        Builder::new("login_challenge")
            .ttl(Duration::from_secs(300))
            .strict_mode()
            .initially_available(requires!(LoginChallengeInit))
            .externally_provided(data_types!(ChallengeProof))
            .from(PasswordAccepted)
            .branch(MfaRequiredBranch)
            .to(MfaRequired, "mfa")
            .to(LoginGranted, "grant")
            .end_branch()
            .from(MfaRequired)
            .auto(ChallengeSent, SendChallengeProcessor)
            .from(ChallengeSent)
            .external(ChallengeVerified, VerifyChallengeGuard)
            .from(ChallengeVerified)
            .auto(LoginGranted, GrantProcessor)
            .on_any_error(LoginDenied)
            .build()
            .expect("LoginChallenge flow definition is invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_and_is_named() {
        assert_eq!(build_login_challenge_flow().name, "login_challenge");
    }
}
