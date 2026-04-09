CREATE TABLE IF NOT EXISTS m2m_clients (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         UUID NOT NULL REFERENCES tenants(id),
    client_id         VARCHAR(120) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    scopes            TEXT NOT NULL DEFAULT '',
    is_active         BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
