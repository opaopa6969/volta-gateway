use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tramli::{
    Builder, FlowContext, FlowDefinition, FlowError, GuardOutput,
    StateProcessor, TransitionGuard, CloneAny,
};

use crate::state::ProxyState;
use crate::proxy::RoutingTable;

// ─── FlowData types ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RequestData {
    pub host: String,
    pub path: String,
    pub method: String,
    pub header_size: usize,
    pub content_length: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RouteTarget {
    pub backend_url: String,
    pub app_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthData {
    pub volta_headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct BackendResponse {
    pub status: u16,
}

// ─── Processors ─────────────────────────────────────────

pub struct RequestValidator {
    pub routing: Arc<RoutingTable>,
}

impl StateProcessor<ProxyState> for RequestValidator {
    fn name(&self) -> &str { "RequestValidator" }
    fn requires(&self) -> Vec<TypeId> { vec![TypeId::of::<RequestData>()] }
    fn produces(&self) -> Vec<TypeId> { vec![] }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let req = ctx.get::<RequestData>()?;

        if req.header_size > 8192 {
            return Err(FlowError::new("BAD_REQUEST", "Headers too large"));
        }
        if let Some(cl) = req.content_length {
            if cl > 10_485_760 {
                return Err(FlowError::new("BAD_REQUEST", "Body too large"));
            }
        }
        if req.host.is_empty() {
            return Err(FlowError::new("BAD_REQUEST", "Missing Host header"));
        }
        if req.path.contains("..") || req.path.contains("//") {
            return Err(FlowError::new("BAD_REQUEST", "Invalid path"));
        }

        let known = self.routing.contains_key(&req.host) || {
            req.host.splitn(2, '.').nth(1)
                .map(|domain| self.routing.contains_key(&format!("*.{domain}")))
                .unwrap_or(false)
        };
        if !known {
            return Err(FlowError::new("BAD_REQUEST", "Unknown host"));
        }

        Ok(())
    }
}

pub struct RoutingResolver {
    pub routing: Arc<RoutingTable>,
}

impl StateProcessor<ProxyState> for RoutingResolver {
    fn name(&self) -> &str { "RoutingResolver" }
    fn requires(&self) -> Vec<TypeId> { vec![TypeId::of::<RequestData>()] }
    fn produces(&self) -> Vec<TypeId> { vec![TypeId::of::<RouteTarget>()] }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let req = ctx.get::<RequestData>()?;
        let host = req.host.clone();

        let (backend, app_id) = self.routing.get(&host)
            .or_else(|| {
                host.splitn(2, '.').nth(1)
                    .and_then(|domain| self.routing.get(&format!("*.{domain}")))
            })
            .ok_or_else(|| FlowError::new("BAD_REQUEST", "No route"))?
            .clone();

        ctx.put(RouteTarget { backend_url: backend, app_id });
        Ok(())
    }
}

pub struct CompletionProcessor;

impl StateProcessor<ProxyState> for CompletionProcessor {
    fn name(&self) -> &str { "CompletionProcessor" }
    fn requires(&self) -> Vec<TypeId> { vec![TypeId::of::<BackendResponse>()] }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, _ctx: &mut FlowContext) -> Result<(), FlowError> { Ok(()) }
}

// ─── Guards ─────────────────────────────────────────────

pub struct AuthGuard;

impl TransitionGuard<ProxyState> for AuthGuard {
    fn name(&self) -> &str { "AuthGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { vec![TypeId::of::<AuthData>()] }

    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<AuthData>() {
            Some(data) => {
                let mut m = HashMap::new();
                m.insert(TypeId::of::<AuthData>(), Box::new(data.clone()) as Box<dyn CloneAny>);
                GuardOutput::Accepted { data: m }
            }
            None => GuardOutput::Rejected { reason: "Auth data not provided".into() },
        }
    }
}

pub struct ForwardGuard;

impl TransitionGuard<ProxyState> for ForwardGuard {
    fn name(&self) -> &str { "ForwardGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![TypeId::of::<RouteTarget>()] }
    fn produces(&self) -> Vec<TypeId> { vec![TypeId::of::<BackendResponse>()] }

    fn validate(&self, ctx: &FlowContext) -> GuardOutput {
        match ctx.find::<BackendResponse>() {
            Some(data) => {
                let mut m = HashMap::new();
                m.insert(TypeId::of::<BackendResponse>(), Box::new(data.clone()) as Box<dyn CloneAny>);
                GuardOutput::Accepted { data: m }
            }
            None => GuardOutput::Rejected { reason: "Backend response not provided".into() },
        }
    }
}

// ─── Flow Definition ────────────────────────────────────

pub fn build_proxy_flow(routing: Arc<RoutingTable>) -> Arc<FlowDefinition<ProxyState>> {
    use ProxyState::*;

    Arc::new(
        Builder::new("proxy")
            .ttl(Duration::from_secs(30))
            .initially_available(vec![TypeId::of::<RequestData>()])

            .from(Received).auto(Validated, RequestValidator { routing: routing.clone() })
            .from(Validated).auto(Routed, RoutingResolver { routing })
            .from(Routed).external(AuthChecked, AuthGuard)
            .from(AuthChecked).external(Forwarded, ForwardGuard)
            .from(Forwarded).auto(Completed, CompletionProcessor)

            .on_any_error(BadGateway)

            .build()
            .expect("Proxy flow definition is invalid")
    )
}
