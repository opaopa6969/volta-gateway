CREATE TABLE IF NOT EXISTS signing_keys (
    kid         VARCHAR(64) PRIMARY KEY,
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL,
    status      VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ
);
