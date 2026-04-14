use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tramli::{
    Builder, FlowContext, FlowDefinition, FlowError, GuardOutput,
    StateProcessor, TransitionGuard, requires, data_types,
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
        // #24 + #52: Reject path traversal (literal and URL-encoded)
        if req.path.contains("..") {
            return Err(FlowError::new("BAD_REQUEST", "Invalid path"));
        }
        // #52: Check URL-decoded variants (%2e%2e, %252e%252e)
        let decoded = urlencoding_decode(&req.path);
        if decoded.contains("..") {
            return Err(FlowError::new("BAD_REQUEST", "Invalid path (encoded traversal)"));
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
            Some(data) => GuardOutput::accept_with(data.clone()),
            None => GuardOutput::rejected("Auth data not provided"),
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
            Some(data) => GuardOutput::accept_with(data.clone()),
            None => GuardOutput::rejected("Backend response not provided"),
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

    let def = Arc::new(
        Builder::new("proxy")
            .ttl(Duration::from_secs(30))
            .strict_mode()  // tramli 3.6: definition-level strict (replaces engine-level)
            .initially_available(requires!(RequestData))
            .externally_provided(data_types!(AuthData, BackendResponse))

            .from(Received).auto(Validated, RequestValidator { routing: routing.clone(), ip_allowlists })
            .from(Validated).auto(Routed, RoutingResolver { routing })
            .from(Routed).external(AuthChecked, AuthGuard)
            .from(AuthChecked).external(Forwarded, ForwardGuard)
            .from(Forwarded).auto(Completed, CompletionProcessor)

            .on_any_error(BadGateway)

            .build()
            .expect("Proxy flow definition is invalid")
    );

    // tramli-plugins 3.2: lint the flow definition at startup
    let mut lint_report = tramli_plugins::api::PluginReport::new();
    for policy in tramli_plugins::lint::default_policies::<ProxyState>() {
        policy(&def, &mut lint_report);
    }
    let findings = lint_report.findings();
    if !findings.is_empty() {
        for finding in findings {
            tracing::warn!(plugin = "lint", severity = %finding.severity, "{}", finding.message);
        }
    }

    def
}

/// Generate diagram bundle (Mermaid + data-flow JSON + markdown summary).
#[allow(dead_code)]
pub fn generate_diagrams(def: &FlowDefinition<ProxyState>) -> tramli_plugins::diagram::DiagramBundle {
    tramli_plugins::diagram::DiagramPlugin::generate(def)
}

/// Generate flow documentation as markdown.
#[allow(dead_code)]
pub fn generate_docs(def: &FlowDefinition<ProxyState>) -> String {
    tramli_plugins::docs::DocumentationPlugin::to_markdown(def)
}

/// Generate BDD test scenarios from flow definition.
#[allow(dead_code)]
pub fn generate_test_plan(def: &FlowDefinition<ProxyState>) -> tramli_plugins::testing::FlowTestPlan {
    tramli_plugins::testing::ScenarioTestPlugin::generate(def)
}

/// #52: Decode percent-encoded path (handles %2e → . , %252e → %2e → . double-encoding)
fn urlencoding_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                hex_val(bytes[i + 1]),
                hex_val(bytes[i + 2]),
            ) {
                result.push((hi << 4 | lo) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    // Second pass for double-encoding (%252e → %2e → .)
    if result.contains('%') && result != input {
        let second = urlencoding_decode(&result);
        if second != result { return second; }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
