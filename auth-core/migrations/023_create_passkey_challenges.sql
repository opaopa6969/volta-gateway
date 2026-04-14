-- Backlog P1 #5: server-side WebAuthn challenge state.
-- webauthn-rs serializes `PasskeyAuthentication` / `PasskeyRegistration`
-- between start and finish; we persist that blob here so login/register
-- ceremonies survive hot-reloads and survive behind a load balancer.

CREATE TABLE IF NOT EXISTS passkey_challenges (
    id         UUID PRIMARY KEY,
    user_id    UUID,                          -- null for login (user not yet resolved)
    state      BYTEA NOT NULL,                -- bincode(serde)-serialised state
    kind       VARCHAR(16) NOT NULL,          -- "auth" | "register"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires ON passkey_challenges(expires_at);
