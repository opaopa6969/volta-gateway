# Spec: Flow definition validation (backlog P2 #9)

## Goal

Run the Java `FlowDefinition.build()` validation suite at auth-server
startup so that a misconfigured flow (unreachable state, missing
branch, terminal outgoing edge, etc.) fails the process before serving
traffic.

## Checks (from `AUTH-STATE-MACHINE-SPEC.md` §3.8)

| # | Check | Error |
|---|---|---|
| 1 | every declared state is reachable from `initial` | `UnreachableState(<state>)` |
| 2 | at least one `initial → terminal` path exists | `NoTerminalPath` |
| 3 | directed graph of `Auto` + `Branch` edges is acyclic | `AutoBranchCycle(<states>)` |
| 4 | each state has at most one outgoing `External` edge | `MultipleExternalEdges(<state>)` |
| 5 | every branch destination is itself a declared state | `UnknownBranchTarget(<state>)` |
| 6 | `requires` / `produces` chain is consistent along every path | `RequirementMismatch(<state>)` *(not checked — auth-core doesn't expose requires yet; reserved)* |
| 7 | `@FlowData` alias uniqueness | *(deferred — Rust flows don't use alias tags yet)* |
| 8 | terminals have no outgoing edges | `TerminalHasOutgoing(<state>)` |

Rust scope: **1, 2, 3, 4, 5, 8** now. 6 and 7 reserved for when
equivalent features land.

## API

`auth-core/src/flow/validate.rs`:

```rust
pub fn validate(flow: &FlowDescriptor) -> Result<(), Vec<FlowError>>;

pub struct FlowDescriptor {
    pub name: &'static str,
    pub states: &'static [&'static str],
    pub initial: &'static str,
    pub terminals: &'static [&'static str],
    pub edges: &'static [Edge],  // reuses mermaid::Edge shape
    /// Subset of `edges` that are "external" (driven by HTTP input).
    /// When empty, rule #4 trivially holds.
    pub external_edges: &'static [Edge],
}
```

Returns **all** errors at once so developers don't chase them one at a
time during wide refactors.

## Hook-in

- `auth-server/src/main.rs` constructs descriptors for the 4 flows
  (they already live as tables in `handlers::viz::flow_tables`) and
  calls `validate()` during startup.
- Any error → log at `error!` level and `std::process::exit(1)`.

## Success criteria

Unit tests in `auth-core/src/flow/validate.rs` cover each error class
with a tiny fixture flow that violates exactly that rule. The 4 real
flows pass validation (regression test).

## Out of scope

- Runtime enforcement (invalid transitions are already blocked by the
  tramli engine).
- Visual diff against Mermaid source (unrelated — `docs/arch/mermaid-flow-diagrams.md`).
