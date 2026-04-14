//! Startup-time validation for flow definitions (backlog P2 #9).
//!
//! Implements the Java `FlowDefinition.build()` rules that matter today:
//! reachability, terminal path, Auto/Branch DAG, external-edge uniqueness,
//! branch-target existence, and terminal outgoing guard.
//!
//! Spec: `auth-server/docs/specs/flow-definition-validation.md`.

use std::collections::{HashMap, HashSet};

use crate::flow::mermaid::Edge;

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

    // Rule 8: terminals have no outgoing edges.
    let terminal_set: HashSet<&'static str> = flow.terminals.iter().copied().collect();
    for e in flow.edges {
        if terminal_set.contains(e.from) {
            errors.push(FlowError::TerminalHasOutgoing(e.from));
        }
    }

    if errors.is_empty() { Ok(()) } else { Err(errors) }
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
    };

    #[test]
    fn good_flow_validates() {
        validate(&GOOD).unwrap();
    }

    #[test]
    fn initial_not_declared_fails() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["B"], initial: "A", terminals: &["B"],
            edges: &[], external_edges: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::InitialNotDeclared("A"))));
    }

    #[test]
    fn unreachable_state_is_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B", "C"], initial: "A", terminals: &["B"],
            edges: &[Edge { from: "A", to: "B", label: "auto" }],
            external_edges: &[],
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::UnreachableState("C"))));
    }

    #[test]
    fn no_terminal_path_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B"], initial: "A", terminals: &["B"],
            edges: &[], external_edges: &[],
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
            external_edges: &[],
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
        };
        let err = validate(&F).unwrap_err();
        assert!(err.iter().any(|e| matches!(e, FlowError::MultipleExternalEdges("A"))));
    }

    #[test]
    fn terminal_with_outgoing_detected() {
        static F: FlowDescriptor = FlowDescriptor {
            name: "f", states: &["A", "B"], initial: "A", terminals: &["A"],
            edges: &[Edge { from: "A", to: "B", label: "auto" }],
            external_edges: &[],
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
            external_edges: &[],
        };
        let err = validate(&F).unwrap_err();
        let unreach = err.iter().any(|e| matches!(e, FlowError::UnreachableState("UNREACH")));
        let term_out = err.iter().any(|e| matches!(e, FlowError::TerminalHasOutgoing("A")));
        assert!(unreach && term_out, "expected both errors, got {:?}", err);
    }
}
