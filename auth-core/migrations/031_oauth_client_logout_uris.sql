-- Phase 5 (auth-methods-landscape §5): OIDC logout channels. RPs may register a
-- back-channel logout endpoint (server-to-server POST of a signed logout_token)
-- and/or a front-channel endpoint (loaded in an iframe from the OP's logout page).

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri  TEXT;
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS frontchannel_logout_uri TEXT;
