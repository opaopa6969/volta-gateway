CREATE TABLE IF NOT EXISTS tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL,
    slug            VARCHAR(50) NOT NULL UNIQUE,
    email_domain    VARCHAR(255),
    auto_join       BOOLEAN NOT NULL DEFAULT false,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    plan            VARCHAR(20) NOT NULL DEFAULT 'FREE',
    max_members     INT NOT NULL DEFAULT 50,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    mfa_required    BOOLEAN NOT NULL DEFAULT false,
    mfa_grace_until TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug);
CREATE INDEX IF NOT EXISTS idx_tenants_domain ON tenants (email_domain) WHERE email_domain IS NOT NULL;
