CREATE TABLE IF NOT EXISTS auth_flow_transitions (
    id           BIGSERIAL PRIMARY KEY,
    flow_id      UUID NOT NULL REFERENCES auth_flows(id) ON DELETE CASCADE,
    from_state   VARCHAR(50),
    to_state     VARCHAR(50) NOT NULL,
    trigger      VARCHAR(100) NOT NULL,
    error_detail VARCHAR(500),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_flow_transitions_flow ON auth_flow_transitions (flow_id);
