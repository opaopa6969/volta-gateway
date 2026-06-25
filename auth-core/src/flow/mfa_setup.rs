//! MFA setup flow — tramli SM (Phase 1 skeleton; definitions only).
//!
//! NOT_CONFIGURED → [external: start] → SETUP_STARTED → SECRET_ISSUED
//!   → CONFIRMATION_PENDING → [external: confirm] → ENABLED
//!   → RECOVERY_CODES_ISSUED. Any error → CANCELLED.
//!
//! TOTP を初期方式とする。secret は KeyCipher(AES-256-GCM) で暗号化、recovery
//! code は SHA256 ハッシュ保存（既存 user_mfa / mfa_recovery_codes を再利用）。
//! 有効化は確認コード検証成功後のみ。SMS/Email OTP は通知抽象まで（弱い方式）。

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MfaSetupState {
    NotConfigured,
    SetupStarted,
    SecretIssued,
    ConfirmationPending,
    Enabled,
    RecoveryCodesIssued,
    Cancelled,
}

impl FlowState for MfaSetupState {
    fn is_terminal(&self) -> bool { matches!(self, Self::RecoveryCodesIssued | Self::Cancelled) }
    fn is_initial(&self) -> bool { matches!(self, Self::NotConfigured) }
    fn all_states() -> &'static [Self] {
        &[
            Self::NotConfigured, Self::SetupStarted, Self::SecretIssued,
            Self::ConfirmationPending, Self::Enabled, Self::RecoveryCodesIssued, Self::Cancelled,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct MfaSetupInit {
    pub user_id: String,
    pub method: String, // "TOTP" initially
}
/// Externally injected when the user begins TOTP setup.
#[derive(Debug, Clone)]
pub struct SetupStart {
    pub method: String,
}
#[derive(Debug, Clone)]
pub struct TotpSecretIssued {
    pub secret_ref: String, // ciphertext ref; never the raw secret
}
#[derive(Debug, Clone)]
pub struct SecretPresented {
    pub provisioning_uri_ref: String,
}
/// Externally injected when the user submits the confirmation code.
#[derive(Debug, Clone)]
pub struct ConfirmResult {
    pub confirmed: bool,
}
#[derive(Debug, Clone)]
pub struct RecoveryCodesResult {
    pub count: u32,
}

struct StartSetupGuard;
impl TransitionGuard<MfaSetupState> for StartSetupGuard {
    fn name(&self) -> &str { "MfaStartSetupGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(SetupStart) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<SetupStart>() {
            Some(s) => GuardOutput::accept_with(s.clone()),
            None => GuardOutput::rejected("setup not started"),
        }
    }
}

struct IssueSecretProcessor;
impl StateProcessor<MfaSetupState> for IssueSecretProcessor {
    fn name(&self) -> &str { "MfaIssueSecret" }
    fn requires(&self) -> Vec<TypeId> { requires!(MfaSetupInit) }
    fn produces(&self) -> Vec<TypeId> { data_types!(TotpSecretIssued) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _init = ctx.get::<MfaSetupInit>()?;
        // Phase 4: generate TOTP secret, encrypt via KeyCipher, persist (inactive).
        ctx.put(TotpSecretIssued { secret_ref: "pending".into() });
        Ok(())
    }
}

struct PresentSecretProcessor;
impl StateProcessor<MfaSetupState> for PresentSecretProcessor {
    fn name(&self) -> &str { "MfaPresentSecret" }
    fn requires(&self) -> Vec<TypeId> { requires!(TotpSecretIssued) }
    fn produces(&self) -> Vec<TypeId> { data_types!(SecretPresented) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _ = ctx.get::<TotpSecretIssued>()?;
        ctx.put(SecretPresented { provisioning_uri_ref: "pending".into() });
        Ok(())
    }
}

struct ConfirmCodeGuard;
impl TransitionGuard<MfaSetupState> for ConfirmCodeGuard {
    fn name(&self) -> &str { "MfaConfirmCodeGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(ConfirmResult) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<ConfirmResult>() {
            Some(r) if r.confirmed => GuardOutput::accept_with(r.clone()),
            Some(_) => GuardOutput::rejected("code invalid"),
            None => GuardOutput::rejected("confirmation code not submitted"),
        }
    }
}

struct IssueRecoveryCodesProcessor;
impl StateProcessor<MfaSetupState> for IssueRecoveryCodesProcessor {
    fn name(&self) -> &str { "MfaIssueRecoveryCodes" }
    fn requires(&self) -> Vec<TypeId> { requires!(ConfirmResult) }
    fn produces(&self) -> Vec<TypeId> { data_types!(RecoveryCodesResult) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _ = ctx.get::<ConfirmResult>()?;
        // Phase 4: activate user_mfa + generate & hash recovery codes.
        ctx.put(RecoveryCodesResult { count: 10 });
        Ok(())
    }
}

pub fn build_mfa_setup_flow() -> Arc<FlowDefinition<MfaSetupState>> {
    use MfaSetupState::*;
    Arc::new(
        Builder::new("mfa_setup")
            .ttl(Duration::from_secs(600))
            .strict_mode()
            .initially_available(requires!(MfaSetupInit))
            .externally_provided(data_types!(SetupStart, ConfirmResult))
            .from(NotConfigured)
            .external(SetupStarted, StartSetupGuard)
            .from(SetupStarted)
            .auto(SecretIssued, IssueSecretProcessor)
            .from(SecretIssued)
            .auto(ConfirmationPending, PresentSecretProcessor)
            .from(ConfirmationPending)
            .external(Enabled, ConfirmCodeGuard)
            .from(Enabled)
            .auto(RecoveryCodesIssued, IssueRecoveryCodesProcessor)
            .on_any_error(Cancelled)
            .build()
            .expect("MfaSetup flow definition is invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_and_is_named() {
        assert_eq!(build_mfa_setup_flow().name, "mfa_setup");
    }
}
