-- Revocable, domain-scoped credentials for temporary human or agent access.
-- Only a SHA-256 hash of the presented secret is stored.
CREATE TABLE IF NOT EXISTS temporary_access_grants (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    subject VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL,
    domains TEXT[] NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_temporary_access_grants_token_hash
    ON temporary_access_grants(token_hash);
CREATE INDEX IF NOT EXISTS idx_temporary_access_grants_tenant
    ON temporary_access_grants(tenant_id, expires_at DESC);
