//! Passkey flow — tramli SM (1:1 from Java PasskeyFlowDef).
//!
//! INIT → CHALLENGE_ISSUED → [external: assertion] → ASSERTION_RECEIVED
//!   → USER_RESOLVED → COMPLETE

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasskeyState {
    Init,
    ChallengeIssued,
    AssertionReceived,
    UserResolved,
    Complete,
    TerminalError,
}

impl FlowState for PasskeyState {
    fn is_terminal(&self) -> bool { matches!(self, Self::Complete | Self::TerminalError) }
    fn is_initial(&self) -> bool { matches!(self, Self::Init) }
    fn all_states() -> &'static [Self] {
        &[Self::Init, Self::ChallengeIssued, Self::AssertionReceived,
          Self::UserResolved, Self::Complete, Self::TerminalError]
    }
}

#[derive(Debug, Clone)]
pub struct PasskeyInitData {
    pub session_id: String,
}

#[derive(Debug, Clone)]
pub struct PasskeyChallenge {
    pub challenge: String,
    pub rp_id: String,
}

#[derive(Debug, Clone)]
pub struct PasskeyAssertion {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct PasskeyUser {
    pub user_id: String,
    pub credential_verified: bool,
}

// Processors
struct ChallengeProcessor;
impl StateProcessor<PasskeyState> for ChallengeProcessor {
    fn name(&self) -> &str { "PasskeyChallenge" }
    fn requires(&self) -> Vec<TypeId> { requires!(PasskeyInitData) }
    fn produces(&self) -> Vec<TypeId> { data_types!(PasskeyChallenge) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _init = ctx.get::<PasskeyInitData>()?;
        ctx.put(PasskeyChallenge {
            challenge: "challenge-placeholder".to_string(),
            rp_id: "unlaxer.org".into(),
        });
        Ok(())
    }
}

struct AssertionGuard;
impl TransitionGuard<PasskeyState> for AssertionGuard {
    fn name(&self) -> &str { "PasskeyAssertionGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(PasskeyAssertion) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<PasskeyAssertion>() {
            Some(data) => {
                let mut m = HashMap::new();
                m.insert(TypeId::of::<PasskeyAssertion>(), Box::new(data.clone()) as Box<dyn CloneAny>);
                GuardOutput::Accepted { data: m }
            }
            None => GuardOutput::Rejected { reason: "assertion not provided".into() },
        }
    }
}

struct VerifyProcessor;
impl StateProcessor<PasskeyState> for VerifyProcessor {
    fn name(&self) -> &str { "PasskeyVerify" }
    fn requires(&self) -> Vec<TypeId> { requires!(PasskeyAssertion, PasskeyChallenge) }
    fn produces(&self) -> Vec<TypeId> { data_types!(PasskeyUser) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _assertion = ctx.get::<PasskeyAssertion>()?;
        // Placeholder — real impl verifies WebAuthn assertion
        ctx.put(PasskeyUser { user_id: String::new(), credential_verified: true });
        Ok(())
    }
}

struct PasskeyCompleteProcessor;
impl StateProcessor<PasskeyState> for PasskeyCompleteProcessor {
    fn name(&self) -> &str { "PasskeyComplete" }
    fn requires(&self) -> Vec<TypeId> { requires!(PasskeyUser) }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let user = ctx.get::<PasskeyUser>()?;
        if !user.credential_verified { return Err(FlowError::new("VERIFY", "credential not verified")); }
        Ok(())
    }
}

pub fn build_passkey_flow() -> Arc<FlowDefinition<PasskeyState>> {
    use PasskeyState::*;
    Arc::new(
        Builder::new("passkey")
            .ttl(Duration::from_secs(120))
            .strict_mode()
            .initially_available(requires!(PasskeyInitData))
            .externally_provided(data_types!(PasskeyAssertion))

            .from(Init).auto(ChallengeIssued, ChallengeProcessor)
            .from(ChallengeIssued).external(AssertionReceived, AssertionGuard)
            .from(AssertionReceived).auto(UserResolved, VerifyProcessor)
            .from(UserResolved).auto(Complete, PasskeyCompleteProcessor)
            .on_any_error(TerminalError)

            .build()
            .expect("Passkey flow definition is invalid")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passkey_flow_builds() {
        let def = build_passkey_flow();
        assert_eq!(def.name, "passkey");
    }

    #[test]
    fn passkey_init_to_challenge() {
        let def = build_passkey_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<PasskeyInitData>(), Box::new(PasskeyInitData { session_id: "s1".into() })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();
        assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), PasskeyState::ChallengeIssued);
    }

    #[test]
    fn passkey_full_flow() {
        let def = build_passkey_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<PasskeyInitData>(), Box::new(PasskeyInitData { session_id: "s1".into() })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();

        let assertion: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<PasskeyAssertion>(), Box::new(PasskeyAssertion {
                credential_id: "cred1".into(), authenticator_data: "ad".into(),
                client_data_json: "cdj".into(), signature: "sig".into(),
            })),
        ];
        engine.resume_and_execute(&flow_id, assertion).unwrap();
        assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), PasskeyState::Complete);
    }
}
