# Spec: Mermaid flow diagrams (backlog P1 #8)

## Goal

`GET /viz/flows` returns each flow's full graph as Mermaid
`stateDiagram-v2` source, ready for tramli-viz / docs rendering.

## Response shape

```json
{
  "flows": [
    {
      "name": "oidc",
      "states": ["INIT", "REDIRECTED", ..., "TERMINAL_ERROR"],
      "initial": "INIT",
      "terminals": ["COMPLETE", "TERMINAL_ERROR"],
      "transitions": [
        {"from": "INIT", "to": "REDIRECTED", "trigger": "auto", "guard": null},
        {"from": "REDIRECTED", "to": "CALLBACK_RECEIVED", "trigger": "external", "guard": "OidcCallbackGuard"}
      ],
      "mermaid": "stateDiagram-v2\n    [*] --> INIT\n    INIT --> REDIRECTED : auto\n    ..."
    },
    { "name": "mfa", ... },
    { "name": "passkey", ... },
    { "name": "invite", ... }
  ]
}
```

## Mermaid format

```text
stateDiagram-v2
    [*] --> INIT
    INIT --> REDIRECTED : auto
    REDIRECTED --> CALLBACK_RECEIVED : OidcCallbackGuard
    CALLBACK_RECEIVED --> TOKEN_EXCHANGED : auto
    ...
    COMPLETE --> [*]
    TERMINAL_ERROR --> [*]
```

Rules:
- `[*] --> <initial>` for each flow's starting state.
- `<terminal> --> [*]` for every terminal.
- Edge labels: `auto` / `external` / `branch(<name>)` / guard name when
  present. Multiple edges between same pair are each emitted.

## Implementation location

New module `auth-core/src/flow/mermaid.rs` with a single free function:

```rust
pub fn render(
    flow_name: &str,
    initial: &str,
    terminals: &[&str],
    transitions: &[Edge],
) -> String;
```

Called from `handlers::viz::list_flows` which wires up the 4 flow
definitions (OIDC / Passkey / MFA / Invite) using static tables — the
underlying `FlowDefinition<S>` trait objects would add generics to the
viz handler, but we have stable state lists already.

## Out of scope

- Tramli-driven generation straight from `FlowDefinition<S>`. Possible
  follow-up — the state tables here are hand-maintained and live
  alongside the flow impls in auth-core. A drift test compares them
  (see "Success criteria").

## Success criteria

- Unit tests: `render` emits expected mermaid for a small fixture.
- Lint: each flow's states in `handlers::viz` must match the state
  enum in auth-core (compile-time assertion via `matches!` in a test).
- `GET /viz/flows` passes a schema check (`mermaid` field present and
  non-empty for every flow).
