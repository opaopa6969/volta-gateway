//! Startup-time validation for flow definitions (backlog P2 #9).
//!
//! Implements the Java `FlowDefinition.build()` rules that matter today:
//! reachability, terminal path, Auto/Branch DAG, external-edge uniqueness,
//! branch-target existence, terminal outgoing guard, requires/produces
//! contract (rule #6), and @FlowData alias uniqueness (rule #7).
//!
//! Spec: `auth-server/docs/specs/flow-definition-validation.md`.

use std::collections::{HashMap, HashSet};

use crate::flow::mermaid::Edge;

/// Declares the data contract for one state processor: which context keys
/// it requires to be present before it runs and which keys it produces.
///
/// Used by rule #6 to verify the requires/produces chain is consistent along
/// every path from `initial` to a terminal.
#[derive(Debug)]
pub struct ProcessorSpec {
    /// The state this processor is attached to.
    pub state: &'static str,
    /// Keys that must have been produced by upstream processors before this
    /// processor runs.
    pub requires: &'static [&'static str],
    /// Keys that this processor adds to the flow context when it succeeds.
    pub produces: &'static [&'static str],
}

/// Shape the validator consumes. Constructed from the flow tables in
/// `auth-server::handlers::viz::flow_tables`.
#[derive(Debug)]
pub struct FlowDescriptor {
    pub name: &'static str,
    pub states: &'static [&'static str],
    pub initial: &'static str,
    pub terminals: &'static [&'static str],
    pub edges: &'static [Edge],
    /// Subset of `edges` that are driven by external (HTTP) input.
    /// Empty when the flow has none.
    pub external_edges: &'static [Edge],
    /// Per-state processor contracts (rule #6). Empty slice disables the
    /// check — backward-compatible with existing `FlowDescriptor` literals.
    pub processors: &'static [ProcessorSpec],
    /// `@FlowData` aliases declared by this flow's context types.
    /// Each entry is `(alias, fully-qualified-class-name)`.
    /// Empty slice disables the per-flow uniqueness check for rule #7.
    pub flow_data_aliases: &'static [(&'static str, &'static str)],
}

#[derive(Debug, PartialEq, Eq)]
pub enum FlowError {
    /// Flow-level: initial state is not in `states`.
    InitialNotDeclared(&'static str),
    /// Flow-level: a terminal is not in `states`.
    TerminalNotDeclared(&'static str),
    /// An edge endpoint isn't declared in `states`.
    UnknownEdgeState { from: &'static str, to: &'static str },
    /// Rule 1: state is not reachable from `initial`.
    UnreachableState(&'static str),
    /// Rule 2: no path from `initial` to any terminal.
    NoTerminalPath,
    /// Rule 3: cycle among Auto/Branch edges (external edges excluded).
    AutoBranchCycle(Vec<&'static str>),
    /// Rule 4: a state has more than one outgoing external edge.
    MultipleExternalEdges(&'static str),
    /// Rule 5: an edge points at a state not declared.
    UnknownBranchTarget(&'static str),
    /// Rule 6: processor at `state` requires `missing` key(s) that no
    /// upstream processor produces along this path.
    RequirementMismatch { state: &'static str, missing: Vec<&'static str> },
    /// Rule 7: two context types in the same flow share the same alias.
    DuplicateAlias {
        alias: &'static str,
        first: &'static str,
        second: &'static str,
    },
    /// Rule 8: a terminal state has an outgoing edge.
    TerminalHasOutgoing(&'static str),
}

/// Run every check and return all violations, or `Ok(())` when the flow is
/// well-formed.
pub fn validate(flow: &FlowDescriptor) -> Result<(), Vec<FlowError>> {
    let mut errors = Vec::new();
    let state_set: HashSet<&'static str> = flow.states.iter().copied().collect();

    // Flow-level sanity.
    if !state_set.contains(flow.initial) {
        errors.push(FlowError::InitialNotDeclared(flow.initial));
    }
    for t in flow.terminals {
        if !state_set.contains(t) {
            errors.push(FlowError::TerminalNotDeclared(t));
        }
    }
    for e in flow.edges {
        if !state_set.contains(e.from) || !state_set.contains(e.to) {
            errors.push(FlowError::UnknownEdgeState { from: e.from, to: e.to });
        }
        if !state_set.contains(e.to) {
            errors.push(FlowError::UnknownBranchTarget(e.to));
        }
    }

    // Bail if the flow is so broken that reachability analysis would crash.
    if errors.iter().any(|e| matches!(e,
        FlowError::InitialNotDeclared(_) | FlowError::UnknownEdgeState { .. })) {
        return Err(errors);
    }

    // Rule 1: reachability.
    let reachable = bfs_reachable(flow);
    for s in flow.states {
        if !reachable.contains(s) {
            errors.push(FlowError::UnreachableState(s));
        }
    }

    // Rule 2: at least one initial→terminal path.
    let has_terminal = flow.terminals.iter().any(|t| reachable.contains(t));
    if !has_terminal && !flow.terminals.is_empty() {
        errors.push(FlowError::NoTerminalPath);
    }

    // Rule 3: Auto + Branch DAG. `external_edges` are excluded.
    let external: HashSet<(&'static str, &'static str, &'static str)> = flow
        .external_edges
        .iter()
        .map(|e| (e.from, e.to, e.label))
        .collect();
    let internal: Vec<&Edge> = flow
        .edges
        .iter()
        .filter(|e| !external.contains(&(e.from, e.to, e.label)))
        .collect();
    if let Some(cycle) = find_cycle(&internal) {
        errors.push(FlowError::AutoBranchCycle(cycle));
    }

    // Rule 4: per-state external-edge count.
    let mut ext_count: HashMap<&'static str, usize> = HashMap::new();
    for e in flow.external_edges {
        *ext_count.entry(e.from).or_default() += 1;
    }
    for (state, n) in ext_count {
        if n > 1 {
            errors.push(FlowError::MultipleExternalEdges(state));
        }
    }

    // Rule 6: requires/produces chain consistent along every path.
    if !flow.processors.is_empty() {
        let proc_map: HashMap<&'static str, &ProcessorSpec> = flow
            .processors
            .iter()
            .map(|p| (p.state, p))
            .collect();
        check_requires_produces(flow, &proc_map, &mut errors);
    }

    // Rule 7: @FlowData alias uniqueness within this flow.
    {
        let mut seen: HashMap<&'static str, &'static str> = HashMap::new();
        for &(alias, fqcn) in flow.flow_data_aliases {
            if let Some(&prev_fqcn) = seen.get(alias) {
                if prev_fqcn != fqcn {
                    errors.push(FlowError::DuplicateAlias { alias, first: prev_fqcn, second: fqcn });
                }
            } else {
                seen.insert(alias, fqcn);
            }
        }
    }

    // Rule 8: terminals have no outgoing edges.
    let terminal_set: HashSet<&'static str> = flow.terminals.iter().copied().collect();
    for e in flow.edges {
        if terminal_set.contains(e.from) {
            errors.push(FlowError::TerminalHasOutgoing(e.from));
        }
    }

    if errors.is_empty() { Ok(()) } else { Err(errors) }
}

/// Validate rule #6 (requires/produces chain) by DFS over all paths from
/// `initial`.  At each state, the processor's `requires` must be a subset of
/// the keys accumulated by upstream `produces`.
fn check_requires_produces(
    flow: &FlowDescriptor,
    proc_map: &HashMap<&'static str, &ProcessorSpec>,
    errors: &mut Vec<FlowError>,
) {
    // Build adjacency list (all edges, including external).
    let mut adj: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    for e in flow.edges {
        adj.entry(e.from).or_default().push(e.to);
    }

    // DFS: (state, accumulated-produced-set)
    // We treat the initial state's produces as seeding the produced set.
    // Use a stack of (state, produced_so_far).
    let mut visited_with_produced: HashMap<&'static str, HashSet<&'static str>> = HashMap::new();
    let mut stack: Vec<(&'static str, HashSet<&'static str>)> = Vec::new();

    // Seed: what the initial state's processor produces.
    let initial_produced: HashSet<&'static str> = proc_map
        .get(flow.initial)
        .map(|p| p.produces.iter().copied().collect())
        .unwrap_or_default();
    stack.push((flow.initial, initial_produced));

    let mut reported: HashSet<&'static str> = HashSet::new();

    while let Some((state, produced)) = stack.pop() {
        // Check this state's processor requirements.
        if let Some(spec) = proc_map.get(state) {
            let missing: Vec<&'static str> = spec
                .requires
                .iter()
                .copied()
                .filter(|&r| !produced.contains(r))
                .collect();
            if !missing.is_empty() && !reported.contains(state) {
                reported.insert(state);
                errors.push(FlowError::RequirementMismatch { state, missing });
            }
        }

        // Propagate to successors.
        let produced_after: HashSet<&'static str> = {
            let mut p = produced.clone();
            if let Some(spec) = proc_map.get(state) {
                p.extend(spec.produces.iter().copied());
            }
            p
        };

        if let Some(nexts) = adj.get(state) {
            for &next in nexts {
                // Only revisit if the produced set is strictly larger (avoids
                // infinite loops on external-edge cycles while still catching gaps).
                let already = visited_with_produced
                    .get(next)
                    .map(|prev| prev.is_superset(&produced_after))
                    .unwrap_or(false);
                if !already {
                    visited_with_produced.insert(next, produced_after.clone());
                    stack.push((next, produced_after.clone()));
                }
            }
        }
    }
}

/// Cross-flow alias uniqueness check for rule #7.
///
/// Call this once at startup with **all** `FlowDescriptor`s.  Returns all
/// `DuplicateAlias` errors where the same alias string is claimed by two
/// different FQCN values across different flows.
pub fn validate_global_aliases(flows: &[&FlowDescriptor]) -> Vec<FlowError> {
    // alias → (fqcn, flow_name)
    let mut global: HashMap<&'static str, (&'static str, &'static str)> = HashMap::new();
    let mut errors = Vec::new();

    for flow in flows {
        for &(alias, fqcn) in flow.flow_data_aliases {
            match global.get(alias) {
                Some(&(prev_fqcn, _)) if prev_fqcn != fqcn => {
                    errors.push(FlowError::DuplicateAlias {
                        alias,
                        first: prev_fqcn,
                        second: fqcn,
                    });
                }
                Some(_) => {} // same fqcn registered twice — allowed
                None => {
                    global.insert(alias, (fqcn, flow.name));
                }
            }
        }
    }
    errors
}

fn bfs_reachable(flow: &FlowDescriptor) -> HashSet<&'static str> {
    let mut adj: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    for e in flow.edges {
        adj.entry(e.from).or_default().push(e.to);
    }
    let mut seen = HashSet::new();
    let mut stack = vec![flow.initial];
    while let Some(s) = stack.pop() {
        if !seen.insert(s) {
            continue;
        }
        if let Some(nexts) = adj.get(s) {
            for &n in nexts {
                if !seen.contains(n) {
                    stack.push(n);
                }
            }
        }
    }
    seen
}

/// Simple DFS cycle detector. Returns the cycle path on first hit.
fn find_cycle(edges: &[&Edge]) -> Option<Vec<&'static str>> {
    let mut adj: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    let mut nodes: HashSet<&'static str> = HashSet::new();
    for e in edges {
        adj.entry(e.from).or_default().push(e.to);
        nodes.insert(e.from);
        nodes.insert(e.to);
    }

    #[derive(Copy, Clone, PartialEq)]
    enum Color { White, Gray, Black }
    let mut color: HashMap<&'static str, Color> =
        nodes.iter().map(|&n| (n, Color::White)).collect();

    for start in nodes.iter().copied() {
        if color[start] != Color::White {
            continue;
        }
        let mut stack: Vec<(&'static str, usize)> = vec![(start, 0)];
        let mut path: Vec<&'static str> = vec![start];
        color.insert(start, Color::Gray);
        while let Some((cur, mut i)) = stack.pop() {
            if let Some(children) = adj.get(cur) {
                if i < children.len() {
                    stack.push((cur, i + 1));
                    let next = children[i];
                    match color[next] {
                        Color::White => {
                            color.insert(next, Color::Gray);
                            path.push(next);
                            stack.push((next, 0));
                            continue;
                        }
                        Color::Gray => {
                            // Found a back-edge — slice path from `next`.
                            if let Some(pos) = path.iter().position(|&n| n == next) {
                                return Some(path[pos..].to_vec());
                            }
                            return Some(vec![next]);
                        }
                        Color::Black => {
                            // Already finished — skip.
                            continue;
                        }
                    }
                }
                // Finished this node.
                i = children.len();
                let _ = i;
            }
            color.insert(cur, Color::Black);
            let _ = path.pop();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn edge(from: &'static str, to: &'static str) -> Edge {
        Edge { from, to, label: "auto" }
    }

    static GOOD: FlowDescriptor = FlowDescriptor {
        name: "good",
        states: &["A", "B", "C"],
        initial: "A",
        terminals: &["C"],
        edges: &[
            Edge { from: "A", to: "B", label: "auto" },
            Edge { from: "B", to: "C", label: "auto" },
        ],
        external_edges: &[],
        processors: &[],
        flow_data_aliases: &[],
    };

    #[test]
    fn good_flow_validates() {
        validate(&GOOD).unwrap();
    }

    #[test]
    fn initial_not_declared_fails() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["B"], initial: "A", terminals: &["B"],
            edges: &[], external_edges: &[], processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::InitialNotDeclared("A"))));
    }

    #[test]
    fn unreachable_state_is_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B", "C"], initial: "A", terminals: &["B"],
            edges: &[Edge { from: "A", to: "B", label: "auto" }],
            external_edges: &[], processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::UnreachableState("C"))));
    }

    #[test]
    fn no_terminal_path_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B"], initial: "A", terminals: &["B"],
            edges: &[], external_edges: &[], processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::NoTerminalPath)));
    }

    #[test]
    fn cycle_in_auto_branch_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B"], initial: "A", terminals: &["B"],
            edges: &[
                Edge { from: "A", to: "B", label: "auto" },
                Edge { from: "B", to: "A", label: "auto" },
            ],
            external_edges: &[], processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::AutoBranchCycle(_))));
    }

    #[test]
    fn multiple_external_edges_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B", "C"], initial: "A", terminals: &["C"],
            edges: &[
                Edge { from: "A", to: "B", label: "Guard1" },
                Edge { from: "A", to: "C", label: "Guard2" },
                Edge { from: "B", to: "C", label: "auto" },
            ],
            external_edges: &[
                Edge { from: "A", to: "B", label: "Guard1" },
                Edge { from: "A", to: "C", label: "Guard2" },
            ],
            processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::MultipleExternalEdges("A"))));
    }

    #[test]
    fn terminal_with_outgoing_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B"], initial: "A", terminals: &["A"],
            edges: &[Edge { from: "A", to: "B", label: "auto" }],
            external_edges: &[], processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::TerminalHasOutgoing("A"))));
    }

    #[test]
    fn collects_all_errors_at_once() {
        // unreachable + terminal-with-outgoing in the same flow
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B", "C", "UNREACH"], initial: "A", terminals: &["A"],
            edges: &[
                Edge { from: "A", to: "B", label: "auto" },
                Edge { from: "B", to: "C", label: "auto" },
            ],
            external_edges: &[], processors: &[], flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        let unreach = err.iter().any(|e| matches!(e, FlowError::UnreachableState("UNREACH")));
        let term_out = err.iter().any(|e| matches!(e, FlowError::TerminalHasOutgoing("A")));
        assert!(unreach && term_out, "expected both errors, got {:?}", err);
    }

    // ── Rule #6: requires / produces ────────────────────────────────────────

    /// A processor at state B requires "token" but no upstream processor
    /// produces it → RequirementMismatch.
    #[test]
    fn requirement_mismatch_is_detected() {
        static PROCS: &[ProcessorSpec] = &[
            ProcessorSpec { state: "A", requires: &[], produces: &["init_data"] },
            ProcessorSpec { state: "B", requires: &["token"], produces: &[] },
        ];
        static F: FlowDescriptor = FlowDescriptor {
            name: "f",
            states: &["A", "B", "C"],
            initial: "A",
            terminals: &["C"],
            edges: &[
                Edge { from: "A", to: "B", label: "auto" },
                Edge { from: "B", to: "C", label: "auto" },
            ],
            external_edges: &[],
            processors: PROCS,
            flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        let found = err.iter().any(|e| matches!(
            e, FlowError::RequirementMismatch { state: "B", missing } if missing.contains(&"token")
        ));
        assert!(found, "expected RequirementMismatch for B, got {:?}", err);
    }

    /// A→B→C where B produces "token" and C requires "token" → valid.
    #[test]
    fn requirement_satisfied_by_upstream_passes() {
        static PROCS: &[ProcessorSpec] = &[
            ProcessorSpec { state: "A", requires: &[], produces: &["init_data"] },
            ProcessorSpec { state: "B", requires: &["init_data"], produces: &["token"] },
            ProcessorSpec { state: "C", requires: &["token"], produces: &[] },
        ];
        static F: FlowDescriptor = FlowDescriptor {
            name: "f",
            states: &["A", "B", "C", "DONE"],
            initial: "A",
            terminals: &["DONE"],
            edges: &[
                Edge { from: "A", to: "B", label: "auto" },
                Edge { from: "B", to: "C", label: "auto" },
                Edge { from: "C", to: "DONE", label: "auto" },
            ],
            external_edges: &[],
            processors: PROCS,
            flow_data_aliases: &[],
        };
        validate(&F).expect("clean flow with satisfied requirements should pass");
    }

    /// Branch paths: one branch satisfies requirements on the common path, the
    /// other does not → mismatch reported.
    #[test]
    fn requirement_mismatch_on_branch_path() {
        // A → B (produces "x") → [C, D]  C requires "y" (not produced)
        static PROCS: &[ProcessorSpec] = &[
            ProcessorSpec { state: "A", requires: &[], produces: &[] },
            ProcessorSpec { state: "B", requires: &[], produces: &["x"] },
            ProcessorSpec { state: "C", requires: &["y"], produces: &[] },
            ProcessorSpec { state: "D", requires: &["x"], produces: &[] },
        ];
        static F: FlowDescriptor = FlowDescriptor {
            name: "f",
            states: &["A", "B", "C", "D"],
            initial: "A",
            terminals: &["C", "D"],
            edges: &[
                Edge { from: "A", to: "B", label: "auto" },
                Edge { from: "B", to: "C", label: "branch_no" },
                Edge { from: "B", to: "D", label: "branch_yes" },
            ],
            external_edges: &[],
            processors: PROCS,
            flow_data_aliases: &[],
        };
        let err = validate(&F).unwrap_err();
        let found = err.iter().any(|e| matches!(
            e, FlowError::RequirementMismatch { state: "C", .. }
        ));
        assert!(found, "expected RequirementMismatch for C, got {:?}", err);
    }

    // ── Rule #7: @FlowData alias uniqueness ──────────────────────────────────

    /// Two context types in the same flow share alias "oidc.token" → DuplicateAlias.
    #[test]
    fn duplicate_alias_within_flow_is_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f",
            states: &["A", "B"],
            initial: "A",
            terminals: &["B"],
            edges: &[Edge { from: "A", to: "B", label: "auto" }],
            external_edges: &[],
            processors: &[],
            flow_data_aliases: &[
                ("oidc.token", "com.example.TokenA"),
                ("oidc.token", "com.example.TokenB"),
            ],
        };
        let err = validate(&F).unwrap_err();
        let found = err.iter().any(|e| matches!(
            e, FlowError::DuplicateAlias { alias: "oidc.token", .. }
        ));
        assert!(found, "expected DuplicateAlias, got {:?}", err);
    }

    /// Same alias, same FQCN registered twice is not an error.
    #[test]
    fn same_alias_same_fqcn_is_allowed() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f",
            states: &["A", "B"],
            initial: "A",
            terminals: &["B"],
            edges: &[Edge { from: "A", to: "B", label: "auto" }],
            external_edges: &[],
            processors: &[],
            flow_data_aliases: &[
                ("oidc.token", "com.example.Token"),
                ("oidc.token", "com.example.Token"),
            ],
        };
        validate(&F).expect("duplicate registration of same alias+fqcn should pass");
    }

    /// Cross-flow: two flows claim the same alias for different FQCNs.
    #[test]
    fn duplicate_alias_across_flows_is_detected() {
        static FLOW_A: FlowDescriptor = FlowDescriptor {
            name: "flow_a",
            states: &["S", "T"],
            initial: "S",
            terminals: &["T"],
            edges: &[Edge { from: "S", to: "T", label: "auto" }],
            external_edges: &[],
            processors: &[],
            flow_data_aliases: &[("shared.alias", "com.example.TypeA")],
        };
        static FLOW_B: FlowDescriptor = FlowDescriptor {
            name: "flow_b",
            states: &["S", "T"],
            initial: "S",
            terminals: &["T"],
            edges: &[Edge { from: "S", to: "T", label: "auto" }],
            external_edges: &[],
            processors: &[],
            flow_data_aliases: &[("shared.alias", "com.example.TypeB")],
        };
        let errs = validate_global_aliases(&[&FLOW_A, &FLOW_B]);
        let found = errs.iter().any(|e| matches!(
            e, FlowError::DuplicateAlias { alias: "shared.alias", .. }
        ));
        assert!(found, "expected cross-flow DuplicateAlias, got {:?}", errs);
    }

    /// Two flows using the same alias for the same FQCN is fine.
    #[test]
    fn same_alias_same_fqcn_cross_flow_is_allowed() {
        static FLOW_A: FlowDescriptor = FlowDescriptor {
            name: "flow_a",
            states: &["S", "T"],
            initial: "S",
            terminals: &["T"],
            edges: &[Edge { from: "S", to: "T", label: "auto" }],
            external_edges: &[],
            processors: &[],
            flow_data_aliases: &[("shared.token", "com.example.Token")],
        };
        static FLOW_B: FlowDescriptor = FlowDescriptor {
            name: "flow_b",
            states: &["S", "T"],
            initial: "S",
            terminals: &["T"],
            edges: &[Edge { from: "S", to: "T", label: "auto" }],
            external_edges: &[],
            processors: &[],
            flow_data_aliases: &[("shared.token", "com.example.Token")],
        };
        let errs = validate_global_aliases(&[&FLOW_A, &FLOW_B]);
        assert!(errs.is_empty(), "same alias+fqcn across flows should be allowed, got {:?}", errs);
    }
}
