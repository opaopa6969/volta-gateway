CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type  VARCHAR(50) NOT NULL,
    actor_id    UUID,
    actor_ip    VARCHAR(45),
    tenant_id   UUID,
    target_type VARCHAR(30),
    target_id   VARCHAR(255),
    detail      JSONB,
    request_id  UUID NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs (tenant_id);
