CREATE TABLE IF NOT EXISTS agent_silence_incidents (
    id BIGSERIAL PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    hardware_id TEXT NOT NULL CHECK (length(hardware_id) BETWEEN 1 AND 512),
    last_seen_at TIMESTAMPTZ NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, hardware_id, last_seen_at)
);

ALTER TABLE agent_silence_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_silence_incidents FORCE ROW LEVEL SECURITY;

CREATE POLICY agent_silence_incidents_tenant_isolation ON agent_silence_incidents
    USING (organization_id = NULLIF(current_setting('aftersec.organization_id', true), '')::UUID)
    WITH CHECK (organization_id = NULLIF(current_setting('aftersec.organization_id', true), '')::UUID);

REVOKE UPDATE, DELETE, TRUNCATE ON agent_silence_incidents FROM PUBLIC;
