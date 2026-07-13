-- Append-only, tenant-isolated live-response audit records.
CREATE TABLE IF NOT EXISTS remote_response_audit (
    id BIGSERIAL PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    endpoint_id UUID NOT NULL REFERENCES endpoints(id),
    command_id TEXT NOT NULL UNIQUE CHECK (length(command_id) BETWEEN 1 AND 128),
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    previous_hash BYTEA NOT NULL CHECK (octet_length(previous_hash) = 32),
    record_hash BYTEA NOT NULL CHECK (octet_length(record_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE remote_response_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE remote_response_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY remote_response_audit_tenant_isolation ON remote_response_audit
    USING (organization_id = NULLIF(current_setting('aftersec.organization_id', true), '')::UUID)
    WITH CHECK (organization_id = NULLIF(current_setting('aftersec.organization_id', true), '')::UUID);

CREATE OR REPLACE FUNCTION reject_remote_response_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'remote response audit records are append-only';
END;
$$;

CREATE TRIGGER remote_response_audit_no_update
BEFORE UPDATE OR DELETE ON remote_response_audit
FOR EACH ROW EXECUTE FUNCTION reject_remote_response_audit_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON remote_response_audit FROM PUBLIC;
