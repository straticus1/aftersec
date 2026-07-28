ALTER TABLE remote_response_audit
    DROP CONSTRAINT IF EXISTS remote_response_audit_command_id_key;

ALTER TABLE remote_response_audit
    ADD CONSTRAINT remote_response_audit_command_status_key
    UNIQUE (command_id, status);

CREATE INDEX IF NOT EXISTS remote_response_audit_command
    ON remote_response_audit (organization_id, command_id, id);
