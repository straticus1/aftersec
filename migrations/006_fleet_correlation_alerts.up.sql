CREATE TABLE IF NOT EXISTS fleet_correlation_alerts (
    id BIGSERIAL PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    kind TEXT NOT NULL CHECK (kind IN ('file_hash', 'ssh_login', 'credential_use')),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 512),
    endpoints TEXT[] NOT NULL CHECK (cardinality(endpoints) >= 2),
    detected_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, kind, value, detected_at)
);

ALTER TABLE fleet_correlation_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_correlation_alerts FORCE ROW LEVEL SECURITY;

CREATE POLICY fleet_correlation_alerts_tenant_isolation ON fleet_correlation_alerts
    USING (organization_id = NULLIF(current_setting('aftersec.organization_id', true), '')::UUID)
    WITH CHECK (organization_id = NULLIF(current_setting('aftersec.organization_id', true), '')::UUID);

REVOKE UPDATE, DELETE, TRUNCATE ON fleet_correlation_alerts FROM PUBLIC;
