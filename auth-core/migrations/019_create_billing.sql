CREATE TABLE IF NOT EXISTS plans (
    id           VARCHAR(30) PRIMARY KEY,
    name         VARCHAR(100) NOT NULL,
    max_members  INT NOT NULL,
    max_apps     INT NOT NULL,
    features     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      UUID NOT NULL REFERENCES tenants(id),
    plan_id        VARCHAR(30) NOT NULL REFERENCES plans(id),
    status         VARCHAR(20) NOT NULL,
    stripe_sub_id  VARCHAR(255),
    started_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ
);

-- Seed default plans
INSERT INTO plans (id, name, max_members, max_apps, features) VALUES
    ('FREE', 'Free', 5, 1, ''),
    ('PRO', 'Pro', 50, 10, 'custom_domain,priority_support'),
    ('ENTERPRISE', 'Enterprise', 500, 100, 'custom_domain,priority_support,sso,scim,audit')
ON CONFLICT DO NOTHING;
