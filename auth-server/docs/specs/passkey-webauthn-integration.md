# Spec: Passkey webauthn-rs integration (backlog P1 #5)

## Goal

Replace the current stub handlers in `handlers/passkey_flow.rs` with
real webauthn-rs ceremony lifecycle: proper challenges, cryptographic
signature verification on finish, and correct credential storage.

## Current state

- `auth_start`: returns `{challenge: uuid, rp_id, timeout}` — **not a
  valid WebAuthn challenge**. A conformant client library will reject
  it.
- `auth_finish`: reads `credential_id` from JSON, looks up in DB, skips
  signature/origin/counter verification.
- `register_start` / `register_finish`: similar stubs.

## Target flow — authentication

```text
POST /auth/passkey/start
   → PasskeyService::start_authentication(user_credentials)
   → save (challenge_id → PasskeyAuthentication state) to passkey_challenges
   → return RequestChallengeResponse + challenge_id

POST /auth/passkey/finish  {challenge_id, credential}
   → consume passkey_challenges row by challenge_id (atomic DELETE)
   → PasskeyService::finish_authentication(credential, state)
   → AuthenticationResult.counter > stored counter → update (atomic)
   → issue session
```

## Target flow — registration

```text
POST /api/v1/users/{uid}/passkeys/register/start
   → require session (uid matches session.user_id)
   → PasskeyService::start_registration(uid, username, display, existing_creds)
   → save (challenge_id → PasskeyRegistration state)
   → return CreationChallengeResponse + challenge_id

POST /api/v1/users/{uid}/passkeys/register/finish  {challenge_id, credential}
   → consume challenge
   → PasskeyService::finish_registration → Passkey
   → PasskeyStore::create(user_id, credential_id, public_key, sign_count)
```

## Challenge storage

New migration + table:

```sql
CREATE TABLE passkey_challenges (
    id         UUID PRIMARY KEY,
    user_id    UUID,  -- nullable for login (UV-only, no known user yet)
    state      BYTEA NOT NULL,  -- bincode-serialised PasskeyAuthentication/Registration
    kind       VARCHAR(16) NOT NULL,  -- "auth" | "register"
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL  -- 5 min default
);
```

New `PasskeyChallengeStore` trait:
- `save(record) -> ()`
- `consume(id) -> Option<record>` (atomic DELETE RETURNING)
- `delete_expired() -> count`

## AppState

- `passkey: Arc<PasskeyService>` — constructed from env:
  - `WEBAUTHN_RP_ID` (`"example.com"`)
  - `WEBAUTHN_RP_ORIGIN` (`"https://auth.example.com"`)

The existing `Cargo.toml` entry enables `feature = "webauthn"` on
auth-core. auth-server needs to opt in via
`volta-auth-core = { path = "...", features = ["postgres", "webauthn"] }`.

## Counter check (issue #17)

Existing `PasskeyStore::update_counter` is atomic (`WHERE sign_count <
$1`). Invoke with `result.counter` from webauthn-rs
`AuthenticationResult`. Rejection → 401 replay.

## Success criteria

- webauthn-rs compliance tests (conformance fixtures) pass.
- Replay of the same credential fails with 401.
- Wrong origin in clientDataJSON fails verification (not looked up at
  request time — webauthn-rs validates against RP config).
- Re-using a challenge_id after `finish` returns 400 (row deleted).

## Out of scope (deferred to P2)

- Multi-RP (one server serving multiple RP origins) — current design
  bakes RP into `AppState`.
- Discoverable-credential (passkey-only, no username) flow — requires
  extra challenge attributes; follow-up.
- FIDO MDS (metadata service) validation — nice to have, not required
  for small deployments.
