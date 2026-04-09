CREATE TABLE IF NOT EXISTS auth_flows (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id           VARCHAR(255) NOT NULL,
    flow_type            VARCHAR(30) NOT NULL,
    current_state        VARCHAR(50) NOT NULL,
    guard_failure_count  INT NOT NULL DEFAULT 0,
    version              INT NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at           TIMESTAMPTZ NOT NULL,
    completed_at         TIMESTAMPTZ,
    exit_state           VARCHAR(50),
    summary              JSONB
);

CREATE INDEX IF NOT EXISTS idx_auth_flows_session ON auth_flows (session_id);
CREATE INDEX IF NOT EXISTS idx_auth_flows_expires ON auth_flows (expires_at) WHERE completed_at IS NULL;
