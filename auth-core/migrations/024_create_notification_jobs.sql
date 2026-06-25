-- Phase 2: notification outbox (separate from the webhook outbox_events).
-- A flow enqueues a job in the SAME tx as its state transition; a worker
-- delivers it after commit via NotificationService and records the result.
-- token/secret 値は payload に入れない（テンプレ変数のみ。OTP 等は worker が
-- token テーブルから引く）。idempotency は correlation_id の UNIQUE で担保。

CREATE TABLE IF NOT EXISTS notification_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel         VARCHAR(16) NOT NULL,        -- EMAIL / SMS / LINE / LOG / DUMMY
    recipient       VARCHAR(320) NOT NULL,       -- email / phone / line-id
    template_id     VARCHAR(64) NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}', -- non-sensitive template vars
    correlation_id  VARCHAR(128) UNIQUE,         -- idempotency (e.g. flow_id:step)
    status          VARCHAR(16) NOT NULL DEFAULT 'pending', -- pending / sent / failed
    attempt_count   INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at         TIMESTAMPTZ,
    last_error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_notification_jobs_pending
    ON notification_jobs (next_attempt_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS notification_logs (
    id          BIGSERIAL PRIMARY KEY,
    job_id      UUID REFERENCES notification_jobs(id) ON DELETE SET NULL,
    channel     VARCHAR(16) NOT NULL,
    provider    VARCHAR(32) NOT NULL,
    recipient   VARCHAR(320) NOT NULL,
    template_id VARCHAR(64) NOT NULL,
    outcome     VARCHAR(16) NOT NULL,            -- sent / failed
    message_id  VARCHAR(255),
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_logs_job ON notification_logs (job_id);
