# Arch: Passkey webauthn-rs integration

## Challenge state serialization

webauthn-rs requires the caller to persist `PasskeyAuthentication` /
`PasskeyRegistration` between start and finish. The library exposes
`danger-allow-state-serialisation` (already enabled) which makes these
types `serde`-serializable.

**Decision**: store the serialized state in a dedicated
`passkey_challenges` table, not in a session cookie. Rationale:

- Session cookie size limit (~4 KB) is close to a registration
  challenge. Authentication is smaller but we want one consistent
  mechanism.
- Cookie state would be readable by the client, which is OK for
  webauthn's threat model (state is authenticated by the signing key)
  but hands them unnecessary introspection.
- DB storage lets an attacker who steals a cookie still fail the
  `consume` step on another request (cookie-replay immunity).

## Why a separate store trait (`PasskeyChallengeStore`) rather than
reusing `OidcFlowStore`

Different column shape (`BYTEA state` instead of `TEXT verifier_encrypted`)
and different lifetime semantics (registration lasts longer than a
login). Keeping them as distinct traits prevents accidental
cross-consumption.

## Rolling the webauthn-rs feature into auth-server

Currently auth-server depends on auth-core **without** the `webauthn`
feature. Adding it increases build time (~30 MB of deps). We accept
that — passkey is a first-class auth method, not an optional one.

If a lean deployment wants to disable passkey entirely, a future
`feature = "passkey"` flag on auth-server itself could gate the module.
Not doing it now.

## Counter replay detection

`AuthenticationResult::counter` from webauthn-rs is already how the
library reports the new counter. We pass it to the existing
`PasskeyStore::update_counter` which atomically checks `new >
stored`. This piggybacks on the P0 #17 fix — no new logic needed here.

## Why not drive the flow via tramli SM (like OIDC/MFA)

Considered — would give us same framework across all flows. Rejected
because webauthn-rs *is* the SM for passkey; wrapping it in tramli adds
indirection without value. Passkey flows are simple (start / finish,
no branching) so the SM benefit is low.

## Error taxonomy

| Error | HTTP | API code |
|---|---|---|
| Missing `challenge_id` | 400 | BAD_REQUEST |
| Unknown / expired challenge | 400 | INVALID_CHALLENGE |
| webauthn-rs finish failure | 401 | PASSKEY_FAILED |
| Counter went backwards | 401 | PASSKEY_FAILED |

The same `PASSKEY_FAILED` code hides specific reasons from the client
— matches Java's behaviour and avoids leaking information about
specific verification failures (origin, signature, counter).

## Test strategy

- Unit: `PasskeyChallengeStore` (save / consume / consume-twice /
  expire).
- Integration: `tests/passkey_flow.rs` uses
  `webauthn_rs::testing::WebauthnTestingExt` to drive a full register →
  login → relog cycle in-process.
