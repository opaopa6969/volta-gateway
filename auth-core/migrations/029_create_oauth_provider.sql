-- Phase 3b (auth-methods-landscape §5): volta as an OpenID Provider (OP).
-- Registered clients, single-use authorization codes (PKCE), rotating refresh
-- tokens (with reuse detection via family_id), and remembered consent.
-- Secrets/codes/tokens は平文保存せず hash のみ。

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash TEXT,                       -- NULL = public client (PKCE only)
    name               VARCHAR(255) NOT NULL,
    redirect_uris      TEXT[] NOT NULL DEFAULT '{}',
    grant_types        TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes             TEXT[] NOT NULL DEFAULT '{openid,email,profile}',
    is_confidential    BOOLEAN NOT NULL DEFAULT false,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    code_hash            VARCHAR(128) PRIMARY KEY,  -- SHA-256 of the code
    client_id            VARCHAR(255) NOT NULL,
    user_id              UUID NOT NULL,
    tenant_id            UUID NOT NULL,
    redirect_uri         TEXT NOT NULL,
    scope                TEXT NOT NULL DEFAULT '',
    nonce                TEXT,
    code_challenge       TEXT,
    code_challenge_method VARCHAR(8),
    expires_at           TIMESTAMPTZ NOT NULL,
    consumed_at          TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash   VARCHAR(128) PRIMARY KEY,          -- SHA-256 of the refresh token
    family_id    UUID NOT NULL,                     -- shared across rotations; reuse → revoke family
    client_id    VARCHAR(255) NOT NULL,
    user_id      UUID NOT NULL,
    tenant_id    UUID NOT NULL,
    scope        TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,                        -- set on rotation or explicit revoke
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_family ON oauth_refresh_tokens (family_id);

CREATE TABLE IF NOT EXISTS oauth_consents (
    user_id    UUID NOT NULL,
    client_id  VARCHAR(255) NOT NULL,
    scope      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);
