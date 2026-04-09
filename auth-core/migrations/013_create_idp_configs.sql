CREATE TABLE IF NOT EXISTS idp_configs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL REFERENCES tenants(id),
    provider_type VARCHAR(32) NOT NULL,
    metadata_url  TEXT,
    issuer        TEXT,
    client_id     TEXT,
    client_secret TEXT,
    x509_cert     TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_active     BOOLEAN NOT NULL DEFAULT true
);
