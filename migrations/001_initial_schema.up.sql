-- Organizations (multi-tenancy)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    license_key VARCHAR(255),
    license_tier VARCHAR(50) DEFAULT 'basic',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    full_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'viewer',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Endpoints (managed clients)
CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    hostname VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL,
    platform_version VARCHAR(100),
    agent_version VARCHAR(50),
    ip_address INET,
    mac_address MACADDR,
    last_seen_at TIMESTAMPTZ,
    enrollment_status VARCHAR(50) DEFAULT 'active',
    enrollment_token_hash VARCHAR(255),
    client_certificate TEXT,
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policies
CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL,
    compliance_framework VARCHAR(100),
    rules JSONB NOT NULL,
    remediation_mode VARCHAR(50) DEFAULT 'manual',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Policy Assignments
CREATE TABLE policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(policy_id, endpoint_id)
);

-- Scans (metadata only - findings stored separately)
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    endpoint_id UUID REFERENCES endpoints(id),
    client_scan_id VARCHAR(255),          -- UUID from client
    scan_type VARCHAR(50),
    status VARCHAR(50) DEFAULT 'completed',
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    passed_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_scans_endpoint ON scans(endpoint_id);
CREATE INDEX idx_scans_started ON scans(started_at DESC);

-- Findings
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES endpoints(id),
    category VARCHAR(100),
    name VARCHAR(255),
    description TEXT,
    severity VARCHAR(20),
    current_value TEXT,
    expected_value TEXT,
    passed BOOLEAN,
    cis_benchmark VARCHAR(50),
    nist_control VARCHAR(50),
    compliance_frameworks JSONB DEFAULT '[]',
    remediation_script TEXT,
    log_context TEXT,
    finding_hash VARCHAR(64),            -- For deduplication
    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_endpoint ON findings(endpoint_id);
CREATE INDEX idx_findings_severity ON findings(severity) WHERE NOT passed;
CREATE INDEX idx_findings_hash ON findings(finding_hash);

-- Syscall Alerts (from client-side monitoring)
CREATE TABLE syscall_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    endpoint_id UUID REFERENCES endpoints(id),
    timestamp TIMESTAMPTZ NOT NULL,
    pid INTEGER,
    command VARCHAR(255),
    pattern VARCHAR(255),
    severity VARCHAR(50),
    details JSONB DEFAULT '{}',
    action_taken VARCHAR(50),            -- kill, monitor, ignore
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_alerts_endpoint ON syscall_alerts(endpoint_id);
CREATE INDEX idx_alerts_timestamp ON syscall_alerts(timestamp DESC);
