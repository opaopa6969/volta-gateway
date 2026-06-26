-- MfaStore upsert uses ON CONFLICT (user_id, type); Postgres requires a matching
-- unique index to exist (even when no conflict occurs). Java created this (V7);
-- it was missing from the Rust schema, so upsert failed on a fresh DB.
CREATE UNIQUE INDEX IF NOT EXISTS user_mfa_user_type_uniq ON user_mfa (user_id, type);
