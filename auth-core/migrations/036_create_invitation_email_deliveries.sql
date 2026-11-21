CREATE TABLE invitation_email_deliveries (
    invitation_id UUID NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
    job_id UUID PRIMARY KEY REFERENCES notification_jobs(id) ON DELETE CASCADE
);

CREATE INDEX invitation_email_deliveries_by_invitation
    ON invitation_email_deliveries (invitation_id);

INSERT INTO invitation_email_deliveries (invitation_id, job_id)
SELECT i.id, j.id
FROM invitations i
JOIN notification_jobs j ON j.correlation_id = 'tenant-invitation:' || i.id::text
WHERE j.channel = 'EMAIL' AND j.template_id = 'tenant-invitation';
