-- Threats: raw enrollment and refresh credentials must never be stored.
-- Codes are organization-scoped, expiring, and atomically single-use.
CREATE TABLE enrollment_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_enrollment_codes_active
    ON enrollment_codes (organization_id, expires_at)
    WHERE used_at IS NULL;

ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS hardware_id VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_org_hardware
    ON endpoints (organization_id, hardware_id)
    WHERE hardware_id IS NOT NULL;

CREATE TABLE enrollment_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    hardware_id VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    attestation_fingerprint BYTEA NOT NULL CHECK (octet_length(attestation_fingerprint) = 32),
    refresh_token_hash BYTEA NOT NULL CHECK (octet_length(refresh_token_hash) = 32),
    certificate_serial VARCHAR(64) NOT NULL,
    certificate_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

REVOKE UPDATE, DELETE ON enrollment_audit FROM PUBLIC;
