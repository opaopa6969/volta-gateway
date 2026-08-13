//! Device Authorization Grant flow — tramli SM (Phase 1 skeleton; definitions
//! only). RFC 8628.
//!
//! PENDING → [external: user approves on a 2nd device] → APPROVED
//!   → [auto: token issued on the device's next poll] → COMPLETED.
//! Denial or TTL expiry → REJECTED.
//!
//! The store (`DeviceGrantStore`) is the authoritative state; this definition
//! exists for `/viz/flows` parity and to document the ceremony. The richer
//! PENDING→APPROVED/DENIED/EXPIRED picture lives in the hand-maintained viz
//! table (as with the passkey flow).

use std::any::TypeId;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceGrantState {
    Pending,
    Approved,
    Completed,
    Rejected,
}

impl FlowState for DeviceGrantState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Rejected)
    }
    fn is_initial(&self) -> bool {
        matches!(self, Self::Pending)
    }
    fn all_states() -> &'static [Self] {
        &[
            Self::Pending,
            Self::Approved,
            Self::Completed,
            Self::Rejected,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct DeviceGrantInit {
    pub client_id: String,
    pub user_code: String,
    pub scope: Option<String>,
}
/// Externally injected when the user approves/denies at the verification page.
#[derive(Debug, Clone)]
pub struct DeviceDecisionProof {
    pub approved: bool,
}

struct DecisionGuard;
impl TransitionGuard<DeviceGrantState> for DecisionGuard {
    fn name(&self) -> &str {
        "DeviceDecisionGuard"
    }
    fn requires(&self) -> Vec<TypeId> {
        vec![]
    }
    fn produces(&self) -> Vec<TypeId> {
        data_types!(DeviceDecisionProof)
    }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<DeviceDecisionProof>() {
            Some(p) if p.approved => GuardOutput::accept_with(p.clone()),
            Some(_) => GuardOutput::rejected("user denied the device authorization"),
            None => GuardOutput::rejected("device authorization not yet decided"),
        }
    }
}

struct IssueTokenProcessor;
impl StateProcessor<DeviceGrantState> for IssueTokenProcessor {
    fn name(&self) -> &str {
        "DeviceIssueToken"
    }
    fn requires(&self) -> Vec<TypeId> {
        requires!(DeviceDecisionProof)
    }
    fn produces(&self) -> Vec<TypeId> {
        vec![]
    }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        // Real token issuance happens in the HTTP layer on the device's poll;
        // here we only assert the decision is present.
        let _ = ctx.get::<DeviceDecisionProof>()?;
        Ok(())
    }
}

pub fn build_device_grant_flow() -> Arc<FlowDefinition<DeviceGrantState>> {
    use DeviceGrantState::*;
    Arc::new(
        Builder::new("device_grant")
            .ttl(Duration::from_secs(600))
            .strict_mode()
            .initially_available(requires!(DeviceGrantInit))
            .externally_provided(data_types!(DeviceDecisionProof))
            .from(Pending)
            .external(Approved, DecisionGuard)
            .from(Approved)
            .auto(Completed, IssueTokenProcessor)
            .on_any_error(Rejected)
            .build()
            .expect("DeviceGrant flow definition is invalid"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds_and_is_named() {
        assert_eq!(build_device_grant_flow().name, "device_grant");
    }
}
