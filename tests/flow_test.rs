use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

use tramli::{FlowEngine, InMemoryFlowStore, CloneAny};

use volta_gateway::flow::{self, RequestData, RouteTarget, AuthData, BackendResponse};
use volta_gateway::proxy::RoutingTable;
use volta_gateway::state::ProxyState;

fn test_routing() -> Arc<RoutingTable> {
    let mut rt = RoutingTable::new();
    rt.insert("app.example.com".into(), (vec!["http://localhost:3000".into()], Some("app-wiki".into())));
    rt.insert("*.example.com".into(), (vec!["http://localhost:3001".into()], None));
    Arc::new(rt)
}

#[test]
fn flow_definition_builds_successfully() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    assert_eq!(def.name, "proxy");
}

#[test]
fn happy_path_auto_chains_to_routed() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);

    let mut engine = FlowEngine::new(InMemoryFlowStore::new());
    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "app.example.com".into(),
            path: "/api/v1/users".into(),
            method: "GET".into(),
            header_size: 200,
            content_length: None,
        })),
    ];

    let flow_id = engine.start_flow(def, "test-session", initial).unwrap();

    // Should auto-chain: RECEIVED → VALIDATED → ROUTED (stops at External)
    let flow = engine.store.get(&flow_id).unwrap();
    assert_eq!(flow.current_state(), ProxyState::Routed);
    assert!(!flow.is_completed());

    // Route target should be in context
    let route = flow.context.get::<RouteTarget>().unwrap();
    assert_eq!(route.backend_url, "http://localhost:3000");
    assert_eq!(route.app_id, Some("app-wiki".into()));
}

#[test]
fn wildcard_routing_works() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    let mut engine = FlowEngine::new(InMemoryFlowStore::new());

    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "other.example.com".into(),
            path: "/".into(),
            method: "GET".into(),
            header_size: 100,
            content_length: None,
        })),
    ];

    let flow_id = engine.start_flow(def, "s1", initial).unwrap();
    let flow = engine.store.get(&flow_id).unwrap();
    assert_eq!(flow.current_state(), ProxyState::Routed);

    let route = flow.context.get::<RouteTarget>().unwrap();
    assert_eq!(route.backend_url, "http://localhost:3001");
}

#[test]
fn unknown_host_goes_to_error() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    let mut engine = FlowEngine::new(InMemoryFlowStore::new());

    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "evil.attacker.com".into(),
            path: "/".into(),
            method: "GET".into(),
            header_size: 100,
            content_length: None,
        })),
    ];

    let flow_id = engine.start_flow(def, "s1", initial).unwrap();
    let flow = engine.store.get(&flow_id).unwrap();
    // Should go to error terminal (BadGateway via on_any_error)
    assert!(flow.is_completed());
}

#[test]
fn path_traversal_rejected() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    let mut engine = FlowEngine::new(InMemoryFlowStore::new());

    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "app.example.com".into(),
            path: "/../../etc/passwd".into(),
            method: "GET".into(),
            header_size: 100,
            content_length: None,
        })),
    ];

    let flow_id = engine.start_flow(def, "s1", initial).unwrap();
    let flow = engine.store.get(&flow_id).unwrap();
    assert!(flow.is_completed()); // error terminal
}

#[test]
fn oversized_headers_rejected() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    let mut engine = FlowEngine::new(InMemoryFlowStore::new());

    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "app.example.com".into(),
            path: "/".into(),
            method: "GET".into(),
            header_size: 10000, // > 8192
            content_length: None,
        })),
    ];

    let flow_id = engine.start_flow(def, "s1", initial).unwrap();
    let flow = engine.store.get(&flow_id).unwrap();
    assert!(flow.is_completed()); // error terminal
}

#[test]
fn full_lifecycle_with_resume() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    let mut engine = FlowEngine::new(InMemoryFlowStore::new());

    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "app.example.com".into(),
            path: "/api/v1/users".into(),
            method: "GET".into(),
            header_size: 200,
            content_length: None,
        })),
    ];

    let flow_id = engine.start_flow(def, "s1", initial).unwrap();
    assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), ProxyState::Routed);

    // Resume with auth data
    let auth_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<AuthData>(), Box::new(AuthData {
            volta_headers: HashMap::from([
                ("x-volta-user-id".into(), "user-123".into()),
            ]),
        })),
    ];
    engine.resume_and_execute(&flow_id, auth_data).unwrap();
    assert_eq!(engine.store.get(&flow_id).unwrap().current_state(), ProxyState::AuthChecked);

    // Resume with backend response
    let resp_data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<BackendResponse>(), Box::new(BackendResponse { status: 200 })),
    ];
    engine.resume_and_execute(&flow_id, resp_data).unwrap();

    let flow = engine.store.get(&flow_id).unwrap();
    assert_eq!(flow.current_state(), ProxyState::Completed);
    assert!(flow.is_completed());

    // Transition log should have all steps
    let log = engine.store.transition_log();
    assert!(log.len() >= 5); // RECEIVED→VALIDATED→ROUTED + AUTH→FORWARDED→COMPLETED
}

#[test]
fn transition_log_records_all_steps() {
    let routing = test_routing();
    let def = flow::build_proxy_flow(routing);
    let mut engine = FlowEngine::new(InMemoryFlowStore::new());

    let initial: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
        (TypeId::of::<RequestData>(), Box::new(RequestData {
            host: "app.example.com".into(),
            path: "/".into(),
            method: "GET".into(),
            header_size: 100,
            content_length: None,
        })),
    ];

    engine.start_flow(def, "s1", initial).unwrap();

    // After start_flow: 2 auto transitions recorded (RECEIVED→VALIDATED, VALIDATED→ROUTED)
    let log = engine.store.transition_log();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].trigger, "RequestValidator");
    assert_eq!(log[1].trigger, "RoutingResolver");
}
