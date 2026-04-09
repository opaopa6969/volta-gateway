CREATE TABLE IF NOT EXISTS sessions (
    id            VARCHAR(255) PRIMARY KEY,
    user_id       VARCHAR(255) NOT NULL,
    tenant_id     VARCHAR(255) NOT NULL,
    return_to     VARCHAR(2048),
    created_at    BIGINT NOT NULL,
    last_active_at BIGINT NOT NULL,
    expires_at    BIGINT NOT NULL,
    invalidated_at BIGINT,
    mfa_verified_at BIGINT,
    ip_address    VARCHAR(45),
    user_agent    TEXT,
    csrf_token    VARCHAR(128),
    email         VARCHAR(255),
    tenant_slug   VARCHAR(50),
    roles         TEXT,
    display_name  VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
