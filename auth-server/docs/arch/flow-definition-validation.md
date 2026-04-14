# Arch: Flow definition validation

## Where validation lives

`auth-core/src/flow/validate.rs`. Same crate as the flows so auth-core
tests can validate them without pulling auth-server in. auth-server
simply calls `validate()` at startup.

## Why collect all errors, not stop at the first

In Java, `FlowDefinition.build()` returns the *first* error. Our port
collects all — debugging a 3-flow-wide refactor is faster when you
see every problem in one log line.

Trade-off: 50 ms extra compute on boot (negligible).

## Why descriptors and not runtime reflection

tramli's `FlowDefinition<S>` is generic over state enum `S`. We cannot
iterate flows uniformly without knowing `S`. Matches `handlers::viz::flow_tables`
approach — hand-maintained descriptor tables with a drift test.

Implicit requirement: the descriptors must be the source of truth for
`viz::list_flows` **and** `validate()`. To avoid drift we could later
generate both from a single source; for now a unit test covers each
flow and a code-review check enforces the rest.

## Cycle detection algorithm

Tarjan SCC over the `Auto` + `Branch` subgraph. Any SCC of size > 1
is a cycle; size-1 SCCs with self-loops also count. Report the
members of the offending SCC in the error so debugging is one step.

`External` edges are deliberately excluded from cycle detection: by
design they gate on external input and can't create infinite loops
without user interaction.

## Rule #4 sub-semantic: "External"

The table we maintain marks each edge's category. Without that
distinction we'd reject legitimate OIDC flows that have multiple
automatic paths from the same state (e.g., branch).

## Reserved rules (#6, #7)

- **#6 requires/produces** — auth-core flows don't currently carry a
  requires/produces contract exposed to reflection. When we add it,
  extend `FlowDescriptor` with `requires: &[&[&str]]` and run
  forward-propagation to detect gaps.
- **#7 @FlowData alias** — same story; add alias maps when the feature
  lands. Validation framework is shape-ready.
