# Arch: Mermaid flow diagrams

## Decision: hand-maintained static tables, not runtime reflection

The Rust tramli `FlowDefinition<S>` isn't generically iterable without
knowing `S` up front. Two options:

**(a)** Expose a `dyn FlowDescribe` trait on every definition and
collect them at runtime. Works but cross-cuts the flow code.

**(b) (picked)** Keep state / transition tables in
`handlers::viz::flow_tables`, and add a drift-detection test that
asserts the tables match the real flow. Simple, keeps flow definitions
free of reflection boilerplate.

Trade-off: manual updates when flows gain a state. Acceptable because
flow shape changes are rare and the drift test catches misses.

## Why rendering lives in auth-core

The Mermaid renderer is a pure function with no deps beyond `String`.
Putting it in auth-core lets the auth-server viz handler call it
directly without reinventing the format, and keeps it available to
any future CLI tooling (`volta-bin` could print diagrams, etc.).

## Edge label choices

Java uses `auto`, `external[Guard]`, `branch[Processor]`. We shorten
to:
- `auto` for deterministic transitions
- guard name (`OidcCallbackGuard`) for external transitions
- `branch(<name>)` for branch transitions

Rationale: shorter labels render better in Mermaid; the full name is
still available in the JSON payload for tramli-viz to decorate.

## No dedup

If two transitions share `(from, to)` but with different triggers, we
emit both. Mermaid handles the double-arrow case fine visually.
