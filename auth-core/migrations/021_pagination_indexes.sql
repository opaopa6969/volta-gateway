-- P2.1 Pagination indexes (parallels Java V22__pagination_indexes.sql).
-- Supports ORDER BY and WHERE clauses used by the paginated admin APIs.

CREATE INDEX IF NOT EXISTS idx_users_email           ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_created_at      ON users(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id      ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at   ON sessions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp  ON audit_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant     ON audit_logs(tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_invitations_tenant    ON invitations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_invitations_expires   ON invitations(expires_at DESC);

CREATE INDEX IF NOT EXISTS idx_memberships_tenant_joined
    ON memberships(tenant_id, joined_at DESC);
