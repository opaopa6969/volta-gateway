-- Phase 4c (auth-methods-landscape §5): silent device memory for risk-based
-- adaptive auth. A per-user hash of the __volta_kd device marker — its ABSENCE
-- signals a new device (a risk factor). Distinct from user-managed trusted
-- devices (migration 018): this is invisible to the user and only feeds risk
-- scoring. Only the hash is stored.

CREATE TABLE IF NOT EXISTS risk_known_devices (
    user_id     UUID NOT NULL,
    device_hash VARCHAR(128) NOT NULL,   -- SHA-256 of the __volta_kd cookie value
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_hash)
);
