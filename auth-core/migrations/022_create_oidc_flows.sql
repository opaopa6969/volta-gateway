-- Backlog P0 #1: DB-backed OIDC flow state (replaces HMAC-signed URL state)
-- + encrypted PKCE verifier storage.
--
-- Java counterpart: `oidc_flows` table populated by `OidcInitProcessor` /
-- consumed atomically by `OidcCallbackGuard`. Rust port follows the same
-- shape so flows can be introspected via the same admin tooling.

CREATE TABLE IF NOT EXISTS oidc_flows (
    id                       UUID PRIMARY KEY,
    -- `state` is the opaque value the IdP echoes back via ?state=...; it is
    -- looked up on callback (single-use, deleted atomically).
    state                    VARCHAR(255) NOT NULL UNIQUE,
    nonce                    VARCHAR(255) NOT NULL,
    -- PKCE verifier is stored encrypted (KeyCipher — AES-GCM / PBKDF2).
    -- Base64-encoded `nonce || ciphertext || tag`.
    code_verifier_encrypted  TEXT NOT NULL,
    -- Post-login redirect target; validated against the allow-list before use.
    return_to                TEXT,
    -- Optional invite code so `/invite/{code}/accept` can be chained.
    invite_code              VARCHAR(64),
    -- IdP tenant context (for multi-IdP deployments).
    tenant_id                UUID,
    -- Housekeeping.
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at               TIMESTAMPTZ NOT NULL
);

-- Fast single-use lookup by opaque state parameter.
CREATE INDEX IF NOT EXISTS idx_oidc_flows_state   ON oidc_flows(state);
-- Janitor sweep of expired rows.
CREATE INDEX IF NOT EXISTS idx_oidc_flows_expires ON oidc_flows(expires_at);
