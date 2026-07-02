-- Phase 4c (auth-methods-landscape §5): risk step-up markers. When adaptive auth
-- decides a login needs an extra factor, the session is marked here. ForwardAuth
-- then routes it through /mfa/challenge even if tenant policy wouldn't normally
-- require MFA — as long as the user has *some* second factor (TOTP or passkey).
-- Per-session so a fresh passkey re-auth (a new, unmarked session) satisfies it.

CREATE TABLE IF NOT EXISTS session_stepup (
    session_id VARCHAR(255) PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
