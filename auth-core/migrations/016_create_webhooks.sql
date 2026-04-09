CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    endpoint_url    TEXT NOT NULL,
    secret          VARCHAR(255) NOT NULL,
    events          TEXT NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS outbox_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    event_type      VARCHAR(80) NOT NULL,
    payload         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    attempt_count   INT DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT now(),
    last_error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_outbox_unpublished ON outbox_events (next_attempt_at) WHERE published_at IS NULL;

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    outbox_event_id  UUID NOT NULL REFERENCES outbox_events(id),
    webhook_id       UUID NOT NULL REFERENCES webhook_subscriptions(id),
    event_type       VARCHAR(80) NOT NULL,
    status           VARCHAR(20) NOT NULL,
    status_code      INT,
    response_body    TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
