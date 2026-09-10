ALTER TABLE temporary_access_grants
    ADD COLUMN IF NOT EXISTS blocked_domains TEXT[] NOT NULL DEFAULT '{}';
