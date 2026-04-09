CREATE TABLE IF NOT EXISTS invitation_usages (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invitation_id UUID NOT NULL REFERENCES invitations(id),
    used_by       UUID NOT NULL REFERENCES users(id),
    used_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
