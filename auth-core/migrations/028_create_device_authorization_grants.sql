-- Phase 1 (auth-methods-landscape §5): OAuth 2.0 Device Authorization Grant
-- (RFC 8628). Input-constrained / native clients get a device_code (polled) +
-- a short human user_code the user approves on a second device (QR carries the
-- verification_uri_complete). device_code は平文保存せず SHA-256(hash) のみ。
-- 期限・承認状態・poll間隔(slow_down用) を属性で保持。

CREATE TABLE IF NOT EXISTS device_authorization_grants (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code_hash  VARCHAR(128) NOT NULL UNIQUE,   -- SHA-256 hex of device_code
    user_code         VARCHAR(16)  NOT NULL UNIQUE,   -- human code, e.g. WDJB-MJHT
    client_id         VARCHAR(255) NOT NULL,
    scope             TEXT,
    status            VARCHAR(16)  NOT NULL DEFAULT 'pending', -- pending/approved/denied/expired
    user_id           UUID,                            -- set on approval
    tenant_id         UUID,                            -- set on approval
    interval_secs     INT          NOT NULL DEFAULT 5,
    last_polled_at    TIMESTAMPTZ,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ  NOT NULL
);

-- user_code lookups during the (rare) approval step; only pending rows matter.
CREATE INDEX IF NOT EXISTS idx_device_grants_user_code
    ON device_authorization_grants (user_code) WHERE status = 'pending';
