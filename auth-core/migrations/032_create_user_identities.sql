-- Phase 5 (auth-methods-landscape §5): account linking. One user can own several
-- federated identities (Google + GitHub + Microsoft…). A login is matched by
-- (provider, subject); a verified email matching an existing user links the new
-- identity to that user instead of creating a duplicate account.

CREATE TABLE IF NOT EXISTS user_identities (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL,
    provider       VARCHAR(64) NOT NULL,     -- google / github / microsoft / …
    subject        VARCHAR(255) NOT NULL,    -- the IdP's stable subject (sub)
    email          VARCHAR(320),
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, subject)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities (user_id);
