//! OIDC flow — tramli SM (1:1 from Java OidcFlowDef).
//!
//! INIT → REDIRECTED → CALLBACK_RECEIVED → TOKEN_EXCHANGED → USER_RESOLVED
//!   → RISK_CHECKED → [branch: COMPLETE | COMPLETE_MFA_PENDING | BLOCKED]
//!   Error: RETRIABLE_ERROR → retry → INIT
//!   Fatal: TERMINAL_ERROR

use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tramli::*;

// ─── State ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OidcState {
    Init,
    Redirected,
    CallbackReceived,
    TokenExchanged,
    UserResolved,
    RiskChecked,
    // Terminal
    Complete,
    CompleteMfaPending,
    Blocked,
    TerminalError,
}

impl FlowState for OidcState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete | Self::CompleteMfaPending | Self::Blocked | Self::TerminalError)
    }
    fn is_initial(&self) -> bool { matches!(self, Self::Init) }
    fn all_states() -> &'static [Self] {
        &[Self::Init, Self::Redirected, Self::CallbackReceived, Self::TokenExchanged,
          Self::UserResolved, Self::RiskChecked, Self::Complete, Self::CompleteMfaPending,
          Self::Blocked, Self::TerminalError]
    }
}

// ─── Flow Data ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct OidcInitData {
    pub provider: String,      // google, github, microsoft, etc.
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub app_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OidcCallbackData {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Clone)]
pub struct OidcTokenData {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OidcUserData {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub is_new_user: bool,
}

#[derive(Debug, Clone)]
pub struct RiskCheckResult {
    pub risk_level: String,  // low, medium, high
    pub mfa_required: bool,
    pub blocked: bool,
}

// ─── Processors ────────────────────────────────────────

struct OidcInitProcessor;
impl StateProcessor<OidcState> for OidcInitProcessor {
    fn name(&self) -> &str { "OidcInit" }
    fn requires(&self) -> Vec<TypeId> { requires!(OidcInitData) }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let data = ctx.get::<OidcInitData>()?;
        if data.provider.is_empty() { return Err(FlowError::new("INIT", "provider required")); }
        if data.redirect_uri.is_empty() { return Err(FlowError::new("INIT", "redirect_uri required")); }
        Ok(())
    }
}

struct TokenExchangeProcessor;
impl StateProcessor<OidcState> for TokenExchangeProcessor {
    fn name(&self) -> &str { "TokenExchange" }
    fn requires(&self) -> Vec<TypeId> { requires!(OidcCallbackData) }
    fn produces(&self) -> Vec<TypeId> { data_types!(OidcTokenData) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let cb = ctx.get::<OidcCallbackData>()?;
        if cb.code.is_empty() { return Err(FlowError::new("CALLBACK", "code required")); }
        // Placeholder — real impl exchanges code for tokens via IdP
        ctx.put(OidcTokenData {
            access_token: format!("at-{}", cb.code),
            id_token: None,
            refresh_token: None,
        });
        Ok(())
    }
}

struct UserResolveProcessor;
impl StateProcessor<OidcState> for UserResolveProcessor {
    fn name(&self) -> &str { "UserResolve" }
    fn requires(&self) -> Vec<TypeId> { requires!(OidcTokenData) }
    fn produces(&self) -> Vec<TypeId> { data_types!(OidcUserData) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _token = ctx.get::<OidcTokenData>()?;
        // Placeholder — real impl fetches userinfo from IdP
        ctx.put(OidcUserData {
            user_id: String::new(), email: String::new(), display_name: String::new(),
            tenant_id: String::new(), roles: vec![], is_new_user: false,
        });
        Ok(())
    }
}

struct RiskCheckProcessor;
impl StateProcessor<OidcState> for RiskCheckProcessor {
    fn name(&self) -> &str { "RiskCheck" }
    fn requires(&self) -> Vec<TypeId> { requires!(OidcUserData) }
    fn produces(&self) -> Vec<TypeId> { data_types!(RiskCheckResult) }
    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let _user = ctx.get::<OidcUserData>()?;
        // Placeholder — real impl checks FraudAlert, device trust
        ctx.put(RiskCheckResult { risk_level: "low".into(), mfa_required: false, blocked: false });
        Ok(())
    }
}

// ─── Branch (Risk → Complete | MfaPending | Blocked) ───

struct RiskBranch;
impl BranchProcessor<OidcState> for RiskBranch {
    fn name(&self) -> &str { "RiskBranch" }
    fn requires(&self) -> Vec<TypeId> { requires!(RiskCheckResult) }
    fn decide(&self, ctx: &FlowContext) -> String {
        match ctx.find::<RiskCheckResult>() {
            Some(risk) => {
                if risk.blocked { return "blocked".into(); }
                if risk.mfa_required { return "mfa_pending".into(); }
                "complete".into()
            }
            None => "complete".into(),
        }
    }
}

// ─── Guards ────────────────────────────────────────────

struct CallbackGuard;
impl TransitionGuard<OidcState> for CallbackGuard {
    fn name(&self) -> &str { "OidcCallbackGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(OidcCallbackData) }
    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<OidcCallbackData>() {
            Some(data) => {
                let mut m = HashMap::new();
                m.insert(TypeId::of::<OidcCallbackData>(), Box::new(data.clone()) as Box<dyn CloneAny>);
                GuardOutput::Accepted { data: m }
            }
            None => GuardOutput::Rejected { reason: "callback data not provided".into() },
        }
    }
}

// ─── Flow Definition ───────────────────────────────────

pub fn build_oidc_flow() -> Arc<FlowDefinition<OidcState>> {
    use OidcState::*;
    Arc::new(
        Builder::new("oidc")
            .ttl(Duration::from_secs(600)) // 10 min for OIDC flow
            .strict_mode()
            .initially_available(requires!(OidcInitData))
            .externally_provided(data_types!(OidcCallbackData))

            .from(Init).auto(Redirected, OidcInitProcessor)
            .from(Redirected).external(CallbackReceived, CallbackGuard)
            .from(CallbackReceived).auto(TokenExchanged, TokenExchangeProcessor)
            .from(TokenExchanged).auto(UserResolved, UserResolveProcessor)
            .from(UserResolved).auto(RiskChecked, RiskCheckProcessor)
            .from(RiskChecked).branch(RiskBranch)
                .to(Complete, "complete")
                .to(CompleteMfaPending, "mfa_pending")
                .to(Blocked, "blocked")
                .end_branch()

            .on_any_error(TerminalError)

            .build()
            .expect("OIDC flow definition is invalid")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_flow_builds() {
        let def = build_oidc_flow();
        assert_eq!(def.name, "oidc");
    }

    #[test]
    fn oidc_flow_init_to_redirected() {
        let def = build_oidc_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<OidcInitData>(), Box::new(OidcInitData {
                provider: "google".into(), redirect_uri: "https://app/callback".into(),
                state: "state123".into(), nonce: "nonce456".into(), app_id: None,
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();
        let flow = engine.store.get(&flow_id).unwrap();
        assert_eq!(flow.current_state(), OidcState::Redirected);
    }

    #[test]
    fn oidc_flow_full_happy_path() {
        let def = build_oidc_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<OidcInitData>(), Box::new(OidcInitData {
                provider: "google".into(), redirect_uri: "https://app/callback".into(),
                state: "s".into(), nonce: "n".into(), app_id: None,
            })),
        ];
        let flow_id = engine.start_flow(def, "test", data).unwrap();

        // Resume with callback
        let cb: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<OidcCallbackData>(), Box::new(OidcCallbackData {
                code: "auth-code-123".into(), state: "s".into(),
            })),
        ];
        engine.resume_and_execute(&flow_id, cb).unwrap();

        let flow = engine.store.get(&flow_id).unwrap();
        assert_eq!(flow.current_state(), OidcState::Complete);
    }
}
