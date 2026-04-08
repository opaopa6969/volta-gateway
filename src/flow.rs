use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tramli::{
    Builder, FlowContext, FlowDefinition, FlowError, GuardOutput,
    StateProcessor, TransitionGuard, CloneAny, requires, data_types,
};

use crate::state::ProxyState;
use crate::proxy::RoutingTable;

// ─── FlowData types ─────────────────────────────────────

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RequestData {
    pub host: String,
    pub path: String,
    pub method: String,
    pub header_size: usize,
    pub content_length: Option<u64>,
    pub client_ip: Option<std::net::IpAddr>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RouteTarget {
    pub backend_url: String,       // selected by round-robin (or first)
    pub backends: Vec<String>,     // all available backends
    pub app_id: Option<String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthData {
    pub volta_headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BackendResponse {
    pub status: u16,
}

// ─── Processors ─────────────────────────────────────────

pub struct RequestValidator {
    pub routing: Arc<RoutingTable>,
    pub ip_allowlists: HashMap<String, Vec<ipnet::IpNet>>,
}

impl StateProcessor<ProxyState> for RequestValidator {
    fn name(&self) -> &str { "RequestValidator" }
    fn requires(&self) -> Vec<TypeId> { requires!(RequestData) }
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

        // GW-17: IP allowlist enforcement
        if let Some(allowlist) = self.ip_allowlists.get(&req.host) {
            if let Some(client_ip) = req.client_ip {
                let allowed = allowlist.iter().any(|net| net.contains(&client_ip));
                if !allowed {
                    return Err(FlowError::new("DENIED", "IP not in allowlist"));
                }
            }
        }

        Ok(())
    }
}

pub struct RoutingResolver {
    pub routing: Arc<RoutingTable>,
}

impl StateProcessor<ProxyState> for RoutingResolver {
    fn name(&self) -> &str { "RoutingResolver" }
    fn requires(&self) -> Vec<TypeId> { requires!(RequestData) }
    fn produces(&self) -> Vec<TypeId> { data_types!(RouteTarget) }

    fn process(&self, ctx: &mut FlowContext) -> Result<(), FlowError> {
        let req = ctx.get::<RequestData>()?;
        let host = req.host.clone();

        let route_info = self.routing.get(&host)
            .or_else(|| {
                host.splitn(2, '.').nth(1)
                    .and_then(|domain| self.routing.get(&format!("*.{domain}")))
            })
            .ok_or_else(|| FlowError::new("BAD_REQUEST", "No route"))?
            .clone();

        let backend = route_info.backends.first()
            .ok_or_else(|| FlowError::new("BAD_REQUEST", "No backends configured"))?
            .clone();

        ctx.put(RouteTarget { backend_url: backend, backends: route_info.backends, app_id: route_info.app_id });
        Ok(())
    }
}

pub struct CompletionProcessor;

impl StateProcessor<ProxyState> for CompletionProcessor {
    fn name(&self) -> &str { "CompletionProcessor" }
    fn requires(&self) -> Vec<TypeId> { requires!(BackendResponse) }
    fn produces(&self) -> Vec<TypeId> { vec![] }
    fn process(&self, _ctx: &mut FlowContext) -> Result<(), FlowError> { Ok(()) }
}

// ─── Guards ─────────────────────────────────────────────

pub struct AuthGuard;

impl TransitionGuard<ProxyState> for AuthGuard {
    fn name(&self) -> &str { "AuthGuard" }
    fn requires(&self) -> Vec<TypeId> { vec![] }
    fn produces(&self) -> Vec<TypeId> { data_types!(AuthData) }

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
    fn requires(&self) -> Vec<TypeId> { requires!(RouteTarget) }
    fn produces(&self) -> Vec<TypeId> { data_types!(BackendResponse) }

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

#[allow(dead_code)]
pub fn build_proxy_flow(routing: Arc<RoutingTable>) -> Arc<FlowDefinition<ProxyState>> {
    build_proxy_flow_with_allowlist(routing, HashMap::new())
}

pub fn build_proxy_flow_with_allowlist(
    routing: Arc<RoutingTable>,
    ip_allowlists: HashMap<String, Vec<ipnet::IpNet>>,
) -> Arc<FlowDefinition<ProxyState>> {
    use ProxyState::*;

    Arc::new(
        Builder::new("proxy")
            .ttl(Duration::from_secs(30))
            .initially_available(requires!(RequestData))

            .from(Received).auto(Validated, RequestValidator { routing: routing.clone(), ip_allowlists })
            .from(Validated).auto(Routed, RoutingResolver { routing })
            .from(Routed).external(AuthChecked, AuthGuard)
            .from(AuthChecked).external(Forwarded, ForwardGuard)
            .from(Forwarded).auto(Completed, CompletionProcessor)

            .on_any_error(BadGateway)

            .build()
            .expect("Proxy flow definition is invalid")
    )
}
