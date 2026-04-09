//! MFA flow — tramli SM (1:1 from Java MfaFlowDef).
//!
//! CHALLENGE_SHOWN → [external: code submitted] → VERIFIED
//! Error: EXPIRED | TERMINAL_ERROR

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MfaState {
    ChallengeShown,
    Verified,
    TerminalError,
    Expired,
}

impl FlowState for MfaState {
    fn is_terminal(&self) -> bool { matches!(self, Self::Verified | Self::TerminalError | Self::Expired) }
    fn is_initial(&self) -> bool { matches!(self, Self::ChallengeShown) }
    fn all_states() -> &'static [Self] {
        &[Self::ChallengeShown, Self::Verified, Self::TerminalError, Self::Expired]
    }
}

#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub session_id: String,
    pub method: String,  // totp, email
}

#[derive(Debug, Clone)]
pub struct MfaCode {
    pub code: String,
    pub valid: bool,
}

struct MfaCodeGuard;
impl TransitionGuard<MfaState> for MfaCodeGuard {
    fn name(&self) -> &str { "MfaCodeGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(MfaCode) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<MfaCode>() {
            Some(data) if data.valid => {
                let mut m = HashMap::new();
                m.insert(TypeId::of::<MfaCode>(), Box::new(data.clone()) as Box<dyn CloneAny>);
                GuardOutput::Accepted { data: m }
            }
            Some(_) => GuardOutput::Rejected { reason: "invalid MFA code".into() },
            None => GuardOutput::Rejected { reason: "MFA code not provided".into() },
        }
    }
}

pub fn build_mfa_flow() -> Arc<FlowDefinition<MfaState>> {
    use MfaState::*;
    Arc::new(
        Builder::new("mfa")
            .ttl(Duration::from_secs(300)) // 5 min for MFA
            .strict_mode()
            .initially_available(requires!(MfaChallenge))
            .externally_provided(data_types!(MfaCode))

            .from(ChallengeShown).external(Verified, MfaCodeGuard)
            .on_any_error(TerminalError)

            .build()
            .expect("MFA flow definition is invalid")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mfa_flow_builds() {
        let def = build_mfa_flow();
        assert_eq!(def.name, "mfa");
    }

    #[test]
    fn mfa_verify_valid_code() {
        let def = build_mfa_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<MfaChallenge>(), Box::new(MfaChallenge {
                session_id: "s1".into(), method: "totp".into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();

        let code: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<MfaCode>(), Box::new(MfaCode { code: "123456".into(), valid: true })),
        ];
        engine.resume_and_execute(&flow_id, code).unwrap();

        let flow = engine.store.get(&flow_id).unwrap();
        assert_eq!(flow.current_state(), MfaState::Verified);
    }

    #[test]
    fn mfa_reject_invalid_code() {
        let def = build_mfa_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<MfaChallenge>(), Box::new(MfaChallenge {
                session_id: "s1".into(), method: "totp".into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();

        let code: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<MfaCode>(), Box::new(MfaCode { code: "wrong".into(), valid: false })),
        ];
        // Guard rejects — flow stays in ChallengeShown
        let _ = engine.resume_and_execute(&flow_id, code);
        let flow = engine.store.get(&flow_id).unwrap();
        assert_eq!(flow.current_state(), MfaState::ChallengeShown);
    }
}
