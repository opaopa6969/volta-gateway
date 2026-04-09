CREATE TABLE IF NOT EXISTS memberships (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id),
    tenant_id  UUID NOT NULL REFERENCES tenants(id),
    role       VARCHAR(30) NOT NULL DEFAULT 'MEMBER',
    joined_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    invited_by UUID REFERENCES users(id),
    is_active  BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_membership_user ON memberships (user_id);
CREATE INDEX IF NOT EXISTS idx_membership_tenant ON memberships (tenant_id);
