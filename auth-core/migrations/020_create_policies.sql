CREATE TABLE IF NOT EXISTS policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    resource    VARCHAR(100) NOT NULL,
    action      VARCHAR(50) NOT NULL,
    condition   JSONB NOT NULL DEFAULT '{}'::jsonb,
    effect      VARCHAR(10) NOT NULL DEFAULT 'allow',
    priority    INT NOT NULL DEFAULT 0,
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
