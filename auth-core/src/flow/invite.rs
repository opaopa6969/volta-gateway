//! Invite flow — tramli SM (1:1 from Java InviteFlowDef).
//!
//! CONSENT_SHOWN → [branch: email match?] → ACCEPTED → COMPLETE
//!   or → ACCOUNT_SWITCHING → [external: accepted] → ACCEPTED → COMPLETE

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InviteState {
    ConsentShown,
    AccountSwitching,
    Accepted,
    Complete,
    TerminalError,
    Expired,
}

impl FlowState for InviteState {
    fn is_terminal(&self) -> bool { matches!(self, Self::Complete | Self::TerminalError | Self::Expired) }
    fn is_initial(&self) -> bool { matches!(self, Self::ConsentShown) }
    fn all_states() -> &'static [Self] {
        &[Self::ConsentShown, Self::AccountSwitching, Self::Accepted,
          Self::Complete, Self::TerminalError, Self::Expired]
    }
}

#[derive(Debug, Clone)]
pub struct InviteData {
    pub invite_code: String,
    pub invite_email: Option<String>,
    pub current_user_email: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone)]
pub struct InviteAcceptance {
    pub accepted: bool,
}

#[derive(Debug, Clone)]
pub struct InviteResult {
    pub user_id: String,
    pub tenant_id: String,
    pub role: String,
}

// Branch: does current user email match invite email?
struct EmailMatchBranch;
impl BranchProcessor<InviteState> for EmailMatchBranch {
    fn name(&self) -> &str { "EmailMatchGuard" }
    fn requires(&self) -> Vec<TypeId> { requires!(InviteData) }
    fn decide(&self, ctx: &FlowContext) -> String {
        match ctx.find::<InviteData>() {
            Some(data) => match &data.invite_email {
                Some(email) if email.eq_ignore_ascii_case(&data.current_user_email) => "match".into(),
                _ => "switch".into(),
            },
            None => "switch".into(),
        }
    }
}

struct AcceptGuard;
impl TransitionGuard<InviteState> for AcceptGuard {
    fn name(&self) -> &str { "InviteAcceptGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(InviteAcceptance) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<InviteAcceptance>() {
            Some(data) if data.accepted => GuardOutput::accept_with(data.clone()),
            Some(_) => GuardOutput::rejected("invite declined"),
            None => GuardOutput::rejected("acceptance not provided"),
        }
    }
}

struct InviteCompleteProcessor;
impl StateProcessor<InviteState> for InviteCompleteProcessor {
    fn name(&self) -> &str { "InviteComplete" }
    fn requires(&self) -> Vec<TypeId> { requires!(InviteData) }
    fn produces(&self) -> Vec<TypeId> { data_types!(InviteResult) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let data = ctx.get::<InviteData>()?;
        ctx.put(InviteResult {
            user_id: String::new(), // filled by real impl
            tenant_id: data.tenant_id.clone(),
            role: "MEMBER".into(),
        });
        Ok(())
    }
}

pub fn build_invite_flow() -> Arc<FlowDefinition<InviteState>> {
    use InviteState::*;
    Arc::new(
        Builder::new("invite")
            .ttl(Duration::from_secs(86400)) // 24h for invite
            .strict_mode()
            .initially_available(requires!(InviteData))
            .externally_provided(data_types!(InviteAcceptance))

            .from(ConsentShown).branch(EmailMatchBranch)
                .to(Accepted, "match")
                .to(AccountSwitching, "switch")
                .end_branch()
            .from(AccountSwitching).external(Accepted, AcceptGuard)
            .from(Accepted).auto(Complete, InviteCompleteProcessor)
            .on_any_error(TerminalError)

            .build()
            .expect("Invite flow definition is invalid")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_flow_builds() {
        let def = build_invite_flow();
        assert_eq!(def.name, "invite");
    }

    #[test]
    fn invite_email_match_auto_accept() {
        let def = build_invite_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<InviteData>(), Box::new(InviteData {
                invite_code: "inv-123".into(),
                invite_email: Some("user@test.com".into()),
                current_user_email: "user@test.com".into(),
                tenant_id: "t-1".into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();
        // Email matches → auto-accepts → Complete
        assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), InviteState::Complete);
    }

    #[test]
    fn invite_email_mismatch_needs_switching() {
        let def = build_invite_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<InviteData>(), Box::new(InviteData {
                invite_code: "inv-123".into(),
                invite_email: Some("other@test.com".into()),
                current_user_email: "user@test.com".into(),
                tenant_id: "t-1".into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();
        // Email doesn't match → AccountSwitching
        assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), InviteState::AccountSwitching);
    }

    #[test]
    fn invite_accept_after_switching() {
        let def = build_invite_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<InviteData>(), Box::new(InviteData {
                invite_code: "inv-123".into(),
                invite_email: None, // no email → switching
                current_user_email: "user@test.com".into(),
                tenant_id: "t-1".into(),
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();
        assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), InviteState::AccountSwitching);

        // User accepts
        let accept: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<InviteAcceptance>(), Box::new(InviteAcceptance { accepted: true })),
        ];
        engine.resume_and_execute(&flow_id, accept).unwrap();
        assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), InviteState::Complete);
    }
}
