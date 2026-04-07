use criterion::{criterion_group, criterion_main, Criterion};
use std::any::TypeId;
use std::collections::HashMap;
use std::sync::Arc;

use tramli::{FlowEngine, InMemoryFlowStore, CloneAny};
use volta_gateway::flow::{self, RequestData};
use volta_gateway::proxy::RoutingTable;

fn test_routing() -> Arc<RoutingTable> {
    let mut rt = RoutingTable::new();
    rt.insert("app.example.com".into(), (vec!["http://localhost:3000".into()], Some("app".into())));
    rt.insert("*.example.com".into(), (vec!["http://localhost:3001".into()], None));
    Arc::new(rt)
}

fn bench_sm_start_flow(c: &mut Criterion) {
    let routing = test_routing();
    let flow_def = flow::build_proxy_flow(routing);

    c.bench_function("sm_start_flow", |b| {
        b.iter(|| {
            let mut engine = FlowEngine::new(InMemoryFlowStore::new());
            let req = RequestData {
                host: "app.example.com".into(),
                path: "/api/v1/users".into(),
                method: "GET".into(),
                header_size: 512,
                content_length: None,
                client_ip: Some("127.0.0.1".parse().unwrap()),
            };
            let data: Vec<(TypeId, Box<dyn CloneAny>)> = vec![
                (TypeId::of::<RequestData>(), Box::new(req)),
            ];
            engine.start_flow(flow_def.clone(), "bench-req", data).unwrap();
        })
    });
}

fn bench_routing_lookup(c: &mut Criterion) {
    let routing = test_routing();

    c.bench_function("routing_lookup_exact", |b| {
        b.iter(|| {
            routing.get("app.example.com")
        })
    });

    c.bench_function("routing_lookup_wildcard", |b| {
        b.iter(|| {
            let host = "sub.example.com";
            routing.get(host).or_else(|| {
                host.splitn(2, '.').nth(1)
                    .and_then(|d| routing.get(&format!("*.{d}")))
            })
        })
    });
}

fn bench_compression_check(c: &mut Criterion) {
    c.bench_function("compression_compressible_check", |b| {
        let ct = "application/json; charset=utf-8";
        b.iter(|| {
            ct.starts_with("text/") || ct.contains("json") || ct.contains("xml") || ct.contains("javascript")
        })
    });
}

criterion_group!(benches, bench_sm_start_flow, bench_routing_lookup, bench_compression_check);
criterion_main!(benches);
