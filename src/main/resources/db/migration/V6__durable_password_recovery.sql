-- Admission records cover every normalized address, including nonexistent accounts.
CREATE TABLE recovery_admissions (
    request_id UUID PRIMARY KEY,
    email_hash CHAR(64) NOT NULL,
    client_ip INET NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX recovery_admissions_time ON recovery_admissions (accepted_at);
CREATE INDEX recovery_admissions_ip ON recovery_admissions (client_ip, accepted_at);
CREATE INDEX recovery_admissions_email ON recovery_admissions (email_hash, accepted_at);

-- No plaintext or encrypted bearer credentials: delivery re-derives a token using
-- an external HMAC key and this random request UUID. Only its hash is in password_resets.
CREATE TABLE recovery_jobs (
    request_id UUID PRIMARY KEY,
    email VARCHAR(254) NOT NULL,
    client_ip INET NOT NULL,
    state VARCHAR(16) NOT NULL DEFAULT 'REQUESTED' CHECK (state IN ('REQUESTED', 'DELIVERY')),
    reset_id UUID REFERENCES password_resets(reset_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    lease_id UUID,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CHECK ((state = 'REQUESTED' AND reset_id IS NULL AND expires_at IS NULL)
        OR (state = 'DELIVERY' AND reset_id IS NOT NULL AND expires_at IS NOT NULL))
);
CREATE INDEX recovery_jobs_available ON recovery_jobs (state, available_at, created_at);
CREATE INDEX recovery_jobs_reset ON recovery_jobs (reset_id);
