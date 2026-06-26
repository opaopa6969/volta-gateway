-- Phase 5: login challenges for Email/SMS/LINE OTP at login (TOTP verifies
-- against user_mfa directly and needs no row here). OTP は平文保存せず
-- code_hash(SHA-256) のみ。期限・試行回数上限・一度きり(consumed_at) を属性で保持。

CREATE TABLE IF NOT EXISTS login_challenges (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL,
    kind          VARCHAR(16) NOT NULL,        -- EMAIL_OTP / SMS_OTP / LINE_OTP
    code_hash     VARCHAR(128) NOT NULL,       -- SHA-256 hex of the OTP
    destination   VARCHAR(320) NOT NULL,       -- where the OTP was sent
    expires_at    TIMESTAMPTZ NOT NULL,
    consumed_at   TIMESTAMPTZ,
    attempt_count INT NOT NULL DEFAULT 0,
    max_attempts  INT NOT NULL DEFAULT 5,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_login_challenges_active
    ON login_challenges (user_id) WHERE consumed_at IS NULL;
