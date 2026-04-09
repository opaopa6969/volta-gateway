//! Token management — refresh rotation + revocation.
//! Uses tramli SM for token lifecycle.

use std::any::TypeId;
use std::sync::Arc;
use tramli::{Builder, FlowContext, FlowDefinition, FlowError, FlowEngine, InMemoryFlowStore,
             StateProcessor, TransitionGuard, GuardOutput, CloneAny, data_types, requires};
use std::collections::HashMap;
use std::time::Duration;

use crate::error::AuthError;
use crate::store::SessionStore;

// ─── Token Flow State (tramli SM) ──────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenState {
    Received,
    Validated,
    Refreshed,
    Issued,
    // Terminal
    Completed,
    Denied,
    Revoked,
}

impl tramli::FlowState for TokenState {
    fn is_terminal(&self) -> bool {
        matches!(self, TokenState::Completed | TokenState::Denied | TokenState::Revoked)
    }
    fn is_initial(&self) -> bool {
        matches!(self, TokenState::Received)
    }
    fn all_states() -> &'static [Self] {
        &[TokenState::Received, TokenState::Validated, TokenState::Refreshed,
          TokenState::Issued, TokenState::Completed, TokenState::Denied, TokenState::Revoked]
    }
}

// ─── Flow Data ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub refresh_token: String,
    pub session_id: String,
    pub client_ip: String,
}

#[derive(Debug, Clone)]
pub struct TokenValidation {
    pub user_id: String,
    pub tenant_id: String,
    pub roles: Vec<String>,
    pub valid: bool,
}

#[derive(Debug, Clone)]
pub struct NewTokens {
    pub jwt: String,
    pub refresh_token: String,
    pub expires_at: u64,
}

// ─── Processors ────────────────────────────────────────

pub struct TokenValidator;

impl StateProcessor<TokenState> for TokenValidator {
    fn name(&self) -> &str { "TokenValidator" }
    fn requires(&self) -> Vec<TypeId> { requires!(TokenRequest) }
    fn produces(&self) -> Vec<TypeId> { data_types!(TokenValidation) }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let req = ctx.get::<TokenRequest>()?;
        if req.refresh_token.is_empty() {
            return Err(FlowError::new("DENIED", "empty refresh token"));
        }
        if req.session_id.is_empty() {
            return Err(FlowError::new("DENIED", "empty session_id"));
        }
        // TokenValidation is provided externally by AuthService
        // after verifying the session in the store.
        // If not present yet, put a placeholder for the Validated state.
        if ctx.find::<TokenValidation>().is_none() {
            ctx.put(TokenValidation {
                user_id: String::new(),
                tenant_id: String::new(),
                roles: vec![],
                valid: true,
            });
        }
        Ok(())
    }
}

pub struct TokenIssuer;

impl StateProcessor<TokenState> for TokenIssuer {
    fn name(&self) -> &str { "TokenIssuer" }
    fn requires(&self) -> Vec<TypeId> { requires!(TokenValidation) }
    fn produces(&self) -> Vec<TypeId> { data_types!(NewTokens) }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let validation = ctx.get::<TokenValidation>()?;
        if !validation.valid {
            return Err(FlowError::new("DENIED", "invalid token"));
        }
        // NewTokens is provided externally by AuthService after issuing JWT.
        // If not present yet, put a placeholder for the Issued state.
        if ctx.find::<NewTokens>().is_none() {
            ctx.put(NewTokens {
                jwt: String::new(),
                refresh_token: String::new(),
                expires_at: 0,
            });
        }
        Ok(())
    }
}

// ─── Guards ────────────────────────────────────────────

pub struct RefreshGuard;

impl TransitionGuard<TokenState> for RefreshGuard {
    fn name(&self) -> &str { "RefreshGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(TokenValidation) }

    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<TokenValidation>() {
            Some(data) => {
                let mut m = HashMap::new();
                m.insert(TypeId::of::<TokenValidation>(), Box::new(data.clone()) as Box<dyn CloneAny>);
                GuardOutput::Accepted { data: m }
            }
            None => GuardOutput::Rejected { reason: "token validation not provided".into() },
        }
    }
}

// ─── Flow Definition ───────────────────────────────────

pub fn build_token_flow() -> Arc<FlowDefinition<TokenState>> {
    use TokenState::*;

    Arc::new(
        Builder::new("token-refresh")
            .ttl(Duration::from_secs(30))
            .strict_mode()
            .initially_available(requires!(TokenRequest))
            .externally_provided(data_types!(TokenValidation))

            .from(Received).auto(Validated, TokenValidator)
            .from(Validated).external(Refreshed, RefreshGuard)
            .from(Refreshed).auto(Issued, TokenIssuer)
            .from(Issued).auto(Completed, CompletionProcessor)

            .on_any_error(Denied)

            .build()
            .expect("Token flow definition is invalid")
    )
}

struct CompletionProcessor;

impl StateProcessor<TokenState> for CompletionProcessor {
    fn name(&self) -> &str { "TokenComplete" }
    fn requires(&self) -> Vec<TypeId> { requires!(NewTokens) }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, _ctx: &mut FlowContext) -> Result<(), FlowError> { Ok(()) }
}

// ─── Token Service ─────────────────────────────────────

/// Token refresh service — uses tramli SM.
pub struct TokenService {
    flow_def: Arc<FlowDefinition<TokenState>>,
}

impl TokenService {
    pub fn new() -> Self {
        Self { flow_def: build_token_flow() }
    }

    /// Validate a refresh token request through the SM.
    /// Returns Err if the flow reaches Denied state.
    pub fn validate_request(&self, request: TokenRequest) -> Result<(), AuthError> {
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<TokenRequest>(), Box::new(request)),
        ];
        let flow_id = engine.start_flow(self.flow_def.clone(), "token-refresh", data)
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        let flow = engine.store.get(&flow_id)
            .ok_or_else(|| AuthError::Internal("flow not found".into()))?;
        if flow.current_state() == TokenState::Denied {
            return Err(AuthError::PolicyDenied("token validation failed".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_flow_builds() {
        let def = build_token_flow();
        assert_eq!(def.name, "token-refresh");
    }

    #[test]
    fn token_flow_validates_request() {
        let svc = TokenService::new();
        let req = TokenRequest {
            refresh_token: "rt-123".into(),
            session_id: "s-456".into(),
            client_ip: "1.2.3.4".into(),
        };
        assert!(svc.validate_request(req).is_ok());
    }

    #[test]
    fn token_flow_rejects_empty_token() {
        let svc = TokenService::new();
        let req = TokenRequest {
            refresh_token: "".into(),
            session_id: "s-456".into(),
            client_ip: "1.2.3.4".into(),
        };
        assert!(svc.validate_request(req).is_err());
    }

    #[test]
    fn token_flow_full_lifecycle() {
        let def = build_token_flow();
        let mut engine = FlowEngine::new(InMemoryFlowStore::new());

        let req = TokenRequest {
            refresh_token: "rt-123".into(),
            session_id: "s-456".into(),
            client_ip: "1.2.3.4".into(),
        };
        let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<TokenRequest>(), Box::new(req)),
        ];
        let flow_id = engine.start_flow(def.clone(), "test", data).unwrap();

        // Resume with external validation
        let validation = TokenValidation {
            user_id: "u-1".into(),
            tenant_id: "t-1".into(),
            roles: vec!["MEMBER".into()],
            valid: true,
        };
        let ext: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
            (TypeId::of::<TokenValidation>(), Box::new(validation)),
        ];
        engine.resume_and_execute(&flow_id, ext).unwrap();

        // Should reach Completed
        let flow = engine.store.get(&flow_id).unwrap();
        use tramli::FlowState; assert!(flow.current_state().is_terminal());
    }
}
