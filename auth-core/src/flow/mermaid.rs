//! Mermaid `stateDiagram-v2` renderer (backlog P1 #8).
//!
//! Reusable renderer consumed by `auth-server::handlers::viz::list_flows`
//! and any future CLI tooling. Pure string formatting — no external deps.

/// One edge in a flow graph.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: &'static str,
    pub to: &'static str,
    /// Short label shown on the arrow (`"auto"`, `"GuardName"`,
    /// `"branch(checker)"`, etc.).
    pub label: &'static str,
}

/// Render a flow into Mermaid `stateDiagram-v2` source.
///
/// - `initial` gets an `[*] --> <initial>` entry arrow.
/// - every state in `terminals` gets a `<terminal> --> [*]` exit arrow.
/// - every edge becomes `from --> to : label`.
pub fn render(
    initial: &str,
    terminals: &[&str],
    edges: &[Edge],
) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("stateDiagram-v2\n");
    out.push_str(&format!("    [*] --> {}\n", initial));
    for e in edges {
        if e.label.is_empty() {
            out.push_str(&format!("    {} --> {}\n", e.from, e.to));
        } else {
            out.push_str(&format!("    {} --> {} : {}\n", e.from, e.to, e.label));
        }
    }
    for t in terminals {
        out.push_str(&format!("    {} --> [*]\n", t));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_flow_renders() {
        let edges = [Edge { from: "A", to: "B", label: "auto" }];
        let out = render("A", &["B"], &edges);
        assert!(out.starts_with("stateDiagram-v2\n"));
        assert!(out.contains("[*] --> A"));
        assert!(out.contains("A --> B : auto"));
        assert!(out.contains("B --> [*]"));
    }

    #[test]
    fn empty_label_renders_without_separator() {
        let edges = [Edge { from: "X", to: "Y", label: "" }];
        let out = render("X", &["Y"], &edges);
        assert!(out.contains("X --> Y\n"));
        assert!(!out.contains("X --> Y : \n"));
    }

    #[test]
    fn multiple_terminals_each_get_exit_arrow() {
        let edges: Vec<Edge> = vec![];
        let out = render("S", &["OK", "ERR"], &edges);
        assert!(out.contains("OK --> [*]"));
        assert!(out.contains("ERR --> [*]"));
    }

    #[test]
    fn duplicate_edges_preserved() {
        let edges = [
            Edge { from: "A", to: "B", label: "on-success" },
            Edge { from: "A", to: "B", label: "on-retry" },
        ];
        let out = render("A", &["B"], &edges);
        assert!(out.contains("A --> B : on-success"));
        assert!(out.contains("A --> B : on-retry"));
    }
}
