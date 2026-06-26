-- Phase 2: email verification tokens (registration / EmailVerificationFlow).
-- token は十分長いランダム値。DBには平文を保存せず token_hash(SHA-256 hex) のみ。
-- 期限(expires_at)・一度きり(used_at)・再送 rate limit(resend_count/last_sent_at)・
-- 失敗回数(attempt_count) は state ではなく属性として保持する。

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         VARCHAR(320) NOT NULL,
    token_hash    VARCHAR(128) NOT NULL UNIQUE,   -- SHA-256 hex of the raw token
    flow_id       UUID,                            -- optional link to auth_flows
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,                     -- one-time use
    attempt_count INT NOT NULL DEFAULT 0,
    resend_count  INT NOT NULL DEFAULT 0,
    last_sent_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evt_email ON email_verification_tokens (email);
CREATE INDEX IF NOT EXISTS idx_evt_expires ON email_verification_tokens (expires_at) WHERE used_at IS NULL;
