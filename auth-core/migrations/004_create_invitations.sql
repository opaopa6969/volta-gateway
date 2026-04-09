CREATE TABLE IF NOT EXISTS invitations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID NOT NULL REFERENCES tenants(id),
    code       VARCHAR(64) NOT NULL UNIQUE,
    email      VARCHAR(255),
    role       VARCHAR(30) NOT NULL DEFAULT 'MEMBER',
    max_uses   INT NOT NULL DEFAULT 1,
    used_count INT NOT NULL DEFAULT 0,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
