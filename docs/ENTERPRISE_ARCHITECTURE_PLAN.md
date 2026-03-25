# ENTERPRISE ARCHITECTURE ASSESSMENT AND ENHANCEMENT PLAN
## AfterSec: Transformation to Enterprise-Grade Security Platform

**Date:** 2026-03-24
**Version:** 1.0
**Prepared For:** AfterSec Enterprise Transformation Initiative

---

## EXECUTIVE SUMMARY

AfterSec demonstrates solid architectural fundamentals with well-separated concerns, comprehensive macOS security scanning capabilities, and innovative features like behavioral threat detection and Starlark-based extensibility. However, significant gaps exist in scalability, persistence, authentication, multi-tenancy, and API maturity that must be addressed to compete with enterprise security platforms like Norton Enterprise.

**Critical Finding:** The current architecture is suitable for single-user deployments but requires fundamental restructuring across 7 major domains to achieve enterprise readiness.

**Timeline Estimate:** 18-24 months for full enterprise transformation across 5 implementation phases.

---

## 1. CURRENT ARCHITECTURE ASSESSMENT

### 1.1 Strengths

**Strong Foundation:**
- Clean separation of concerns across packages (`pkg/core`, `pkg/scanners`, `pkg/forensics`, etc.)
- Well-structured domain models (`Finding`, `SecurityState`, `Config`)
- Cobra-based CLI provides good extensibility foundation
- Plugin system via Starlark enables user extensibility
- Comprehensive macOS security checks aligned with CIS benchmarks
- Innovative behavioral analysis and syscall monitoring capabilities

**Security Posture:**
- API key authentication via bearer tokens
- Constant-time comparison for API key validation
- Path traversal protection in storage layer
- Proper file permissions (0600/0700) on sensitive data
- Integration with macOS security primitives (SIP, Gatekeeper, TCC, FileVault)

**Code Quality:**
- Consistent error handling patterns
- Mutex protection for concurrent access
- Progress callback pattern for long-running operations
- Clean abstraction between CLI, GUI, daemon, and SDK

### 1.2 Critical Gaps and Technical Debt

#### **1.2.1 Data Persistence Layer - CRITICAL**

**Current State:**
- File-based storage in `~/.aftersec/` using JSON serialization
- No database, no transactions, no query optimization
- Limited to single-machine deployments
- No support for concurrent writes across multiple endpoints

**Risks:**
- Cannot scale beyond single user/machine
- No ACID guarantees for commit operations
- File corruption risk during concurrent access
- No efficient querying for compliance reports
- History searches require full file scan

**Impact:** Blocking issue for any multi-endpoint deployment

**Files Affected:**
- `pkg/storage/manager.go`

---

#### **1.2.2 API Layer - HIGH PRIORITY**

**Current State:**
- Basic HTTP server with 2 endpoints (`/api/v1/health`, `/api/v1/posture`)
- No versioning strategy beyond URL prefix
- No rate limiting, pagination, or filtering
- No GraphQL support
- No OpenAPI/Swagger documentation
- No request validation or schema enforcement
- Hardcoded to localhost:8080
- Missing critical endpoints for:
  - Policy management
  - Scan triggering
  - Remediation execution
  - User management
  - Audit logging
  - Webhook subscriptions

**Risks:**
- API breaking changes will break all integrations
- No protection against DoS attacks
- Cannot support complex queries across endpoints
- No discoverability for third-party developers

**Impact:** Prevents enterprise integrations and automation

**Files Affected:**
- `pkg/api/server.go`

---

#### **1.2.3 Authentication and Authorization - CRITICAL**

**Current State:**
- Single API key stored in config file
- No user management system
- No role-based access control (RBAC)
- No SSO/SAML support
- No session management
- No OAuth2 flows
- No audit trail of who performed actions

**Risks:**
- Single compromised key exposes entire system
- Cannot differentiate between users or services
- No way to implement principle of least privilege
- Compliance failures for SOC2/ISO27001

**Impact:** Security vulnerability and compliance blocker

**Files Affected:**
- `pkg/api/server.go`
- `pkg/core/config.go`

---

#### **1.2.4 Multi-Tenancy - CRITICAL**

**Current State:**
- No concept of organizations, teams, or tenants
- All data stored in single global namespace
- No data isolation between customers

**Risks:**
- Cannot deploy as SaaS platform
- Data leakage between organizations
- Cannot support MSP/reseller models

**Impact:** Architecture blocker for enterprise/cloud deployment

---

#### **1.2.5 Background Daemon - MEDIUM**

**Current State:**
- Fixed 6-hour scan interval
- No intelligent scheduling based on risk
- No resource limits (CPU/memory throttling)
- Hardcoded alert logging to `/var/log/aftersecd-alerts.log`
- No integration with centralized logging systems
- No health check endpoints for orchestration
- No graceful shutdown handling for rolling updates

**Risks:**
- Resource exhaustion on production systems
- Cannot adapt to high-risk situations
- Daemon crashes lose in-flight scan data

**Impact:** Operational reliability issues at scale

**Files Affected:**
- `cmd/aftersecd/main.go`

---

#### **1.2.6 Observability - HIGH PRIORITY**

**Current State:**
- Basic logging to stdout/files
- No structured logging (JSON)
- No metrics collection (Prometheus)
- No distributed tracing
- No performance profiling endpoints
- No alerting integration

**Risks:**
- Cannot diagnose production issues
- No visibility into performance bottlenecks
- Cannot set SLAs/SLOs

**Impact:** Operations team cannot maintain production system

---

#### **1.2.7 Deployment Infrastructure - HIGH PRIORITY**

**Current State:**
- No containerization
- No Kubernetes support
- No infrastructure as code
- No CI/CD pipeline definitions
- No package management (homebrew formula, etc.)
- No automated testing beyond manual verification

**Risks:**
- Difficult to deploy consistently
- Cannot scale horizontally
- No rollback capability
- Manual deployments error-prone

**Impact:** Prevents cloud and on-prem enterprise deployments

---

#### **1.2.8 SDK and Client Libraries - MEDIUM**

**Current State:**
- Go SDK exists (`afterseclib/`) with basic operations
- No Python, JavaScript, Ruby, or .NET SDKs
- No automation framework integrations (Ansible, Terraform)

**Risks:**
- Limits adoption by DevOps/security teams
- Cannot integrate with existing automation

**Impact:** Reduced market adoption

**Files Affected:**
- `afterseclib/`

---

### 1.3 Security Vulnerabilities

**Identified Issues:**

1. **API Key Management:** Keys stored in plaintext config file - should use encrypted storage or secrets manager
2. **No TLS Enforcement:** API server runs HTTP only (localhost:8080) - needs TLS 1.3 for production
3. **No Input Validation:** API endpoints don't validate request schemas
4. **Privilege Escalation:** `core.RunPrivileged()` uses `osascript` which could be exploited if scripts aren't properly sanitized
5. **File Permissions:** While home directory has 0700, no encryption at rest for sensitive findings data

**Recommendations:**
- Integrate HashiCorp Vault for secrets
- Enforce mTLS for daemon-to-server communication
- Implement comprehensive input validation with JSON Schema
- Sandbox script execution or use declarative remediation policies
- Encrypt all stored security findings with AES-256-GCM

---

## 2. ENTERPRISE ARCHITECTURE DESIGN

### 2.1 Target Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                            │
├──────────────┬──────────────┬──────────────┬────────────────────────┤
│ Web Dashboard│  CLI Tool    │  Mobile App  │  IDE Plugins           │
│  (React/Next)│  (Go/Cobra)  │  (Flutter)   │  (VSCode, IntelliJ)    │
└──────┬───────┴──────┬───────┴──────┬───────┴────────┬───────────────┘
       │              │              │                │
┌──────▼──────────────▼──────────────▼────────────────▼───────────────┐
│                      API GATEWAY LAYER                               │
│  ┌────────────┐ ┌──────────────┐ ┌─────────────┐ ┌──────────────┐  │
│  │  Kong/     │ │  Rate        │ │  Auth       │ │  Request     │  │
│  │  Traefik   │ │  Limiting    │ │  Middleware │ │  Validation  │  │
│  └────────────┘ └──────────────┘ └─────────────┘ └──────────────┘  │
└──────┬───────────────────────────────────────────────────────────────┘
       │
┌──────▼───────────────────────────────────────────────────────────────┐
│                      APPLICATION LAYER                               │
│  ┌─────────────────┐  ┌──────────────────┐  ┌───────────────────┐   │
│  │  REST API       │  │  GraphQL API     │  │  gRPC Services    │   │
│  │  Service        │  │  Service         │  │  (Internal)       │   │
│  │  (Go/Gin)       │  │  (Go/gqlgen)     │  │                   │   │
│  └────────┬────────┘  └────────┬─────────┘  └─────────┬─────────┘   │
│           │                    │                       │             │
│  ┌────────▼────────────────────▼───────────────────────▼─────────┐   │
│  │              BUSINESS LOGIC SERVICES                          │   │
│  │                                                                │   │
│  │  ┌──────────────┐  ┌───────────────┐  ┌────────────────────┐ │   │
│  │  │  Policy      │  │  Scan         │  │  Compliance        │ │   │
│  │  │  Engine      │  │  Orchestrator │  │  Reporter          │ │   │
│  │  └──────────────┘  └───────────────┘  └────────────────────┘ │   │
│  │                                                                │   │
│  │  ┌──────────────┐  ┌───────────────┐  ┌────────────────────┐ │   │
│  │  │  User/Org    │  │  Remediation  │  │  Alert/Webhook     │ │   │
│  │  │  Management  │  │  Executor     │  │  Dispatcher        │ │   │
│  │  └──────────────┘  └───────────────┘  └────────────────────┘ │   │
│  │                                                                │   │
│  │  ┌──────────────┐  ┌───────────────┐  ┌────────────────────┐ │   │
│  │  │  License     │  │  Plugin       │  │  Telemetry         │ │   │
│  │  │  Validator   │  │  Manager      │  │  Collector         │ │   │
│  │  └──────────────┘  └───────────────┘  └────────────────────┘ │   │
│  └────────────────────────────────────────────────────────────────┘   │
└──────┬─────────────────────────────────────────────────────────────┬──┘
       │                                                             │
┌──────▼─────────────────────────────────────────┐  ┌───────────────▼───┐
│           MESSAGE QUEUE LAYER                  │  │   CACHING LAYER   │
│  ┌──────────────────────────────────────────┐  │  │  ┌─────────────┐  │
│  │  RabbitMQ / AWS SQS                      │  │  │  │  Redis      │  │
│  │  - Scan jobs queue                       │  │  │  │  - Sessions │  │
│  │  - Remediation jobs queue                │  │  │  │  - API cache│  │
│  │  - Webhook delivery queue                │  │  │  │  - Rate lim │  │
│  │  - Report generation queue               │  │  │  └─────────────┘  │
│  └──────────────────────────────────────────┘  │  └───────────────────┘
└────────────────────────────────────────────────┘
       │
┌──────▼───────────────────────────────────────────────────────────────┐
│                      DATA PERSISTENCE LAYER                          │
│  ┌─────────────────────┐  ┌──────────────────┐  ┌─────────────────┐  │
│  │  PostgreSQL         │  │  TimescaleDB     │  │  S3/MinIO       │  │
│  │  - Organizations    │  │  (Time-series)   │  │  - Large scans  │  │
│  │  - Users            │  │  - Scan history  │  │  - Export files │  │
│  │  - Policies         │  │  - Metrics       │  │  - Backups      │  │
│  │  - Endpoints        │  │  - Audit logs    │  │                 │  │
│  │  - Findings         │  │                  │  │                 │  │
│  └─────────────────────┘  └──────────────────┘  └─────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                      AGENT LAYER (ENDPOINTS)                         │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  AfterSec Agent (aftersecd) - Runs on each managed endpoint    │  │
│  │  - Local security scanning                                     │  │
│  │  - Syscall monitoring (dtrace/eBPF)                           │  │
│  │  - Policy enforcement                                          │  │
│  │  - Remediation execution                                       │  │
│  │  - Heartbeat & telemetry                                       │  │
│  │  - gRPC/HTTPS communication to control plane                  │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                   OBSERVABILITY LAYER                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │  Prometheus  │  │  Grafana     │  │  Jaeger (Tracing)        │   │
│  │  (Metrics)   │  │  (Dashboards)│  │                          │   │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │  ELK Stack / Loki (Centralized Logging)                      │   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

### 2.2 Database Schema Design

#### 2.2.1 Core Entities

**PostgreSQL Schema (Production-Grade)**

```sql
-- ============================================================================
-- MULTI-TENANCY & IDENTITY
-- ============================================================================

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    license_key VARCHAR(255),
    license_tier VARCHAR(50) NOT NULL DEFAULT 'basic', -- basic, professional, enterprise
    license_seats INTEGER,
    license_expiry TIMESTAMPTZ,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT valid_tier CHECK (license_tier IN ('basic', 'professional', 'enterprise'))
);

CREATE INDEX idx_orgs_slug ON organizations(slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_orgs_license ON organizations(license_key) WHERE deleted_at IS NULL;

-- ============================================================================

CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(organization_id, name)
);

CREATE INDEX idx_teams_org ON teams(organization_id);

-- ============================================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255), -- nullable for SSO users
    full_name VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'viewer', -- admin, security_analyst, auditor, developer, viewer
    sso_provider VARCHAR(50), -- saml, oauth2, ldap
    sso_subject VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    api_keys JSONB DEFAULT '[]', -- array of API key metadata
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT valid_role CHECK (role IN ('admin', 'security_analyst', 'auditor', 'developer', 'viewer'))
);

CREATE INDEX idx_users_org ON users(organization_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_sso ON users(sso_provider, sso_subject) WHERE deleted_at IS NULL;

-- ============================================================================

CREATE TABLE team_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

CREATE INDEX idx_team_members ON team_memberships(team_id);
CREATE INDEX idx_user_teams ON team_memberships(user_id);

-- ============================================================================
-- ENDPOINTS & AGENTS
-- ============================================================================

CREATE TABLE endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
    hostname VARCHAR(255) NOT NULL,
    platform VARCHAR(50) NOT NULL, -- macos, linux, windows
    platform_version VARCHAR(100),
    agent_version VARCHAR(50) NOT NULL,
    ip_address INET,
    mac_address MACADDR,
    last_seen_at TIMESTAMPTZ,
    enrollment_token VARCHAR(255),
    enrollment_status VARCHAR(50) DEFAULT 'pending', -- pending, active, inactive, revoked
    tags JSONB DEFAULT '[]',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT valid_platform CHECK (platform IN ('macos', 'linux', 'windows')),
    CONSTRAINT valid_enrollment CHECK (enrollment_status IN ('pending', 'active', 'inactive', 'revoked'))
);

CREATE INDEX idx_endpoints_org ON endpoints(organization_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_endpoints_team ON endpoints(team_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_endpoints_status ON endpoints(enrollment_status) WHERE deleted_at IS NULL;
CREATE INDEX idx_endpoints_last_seen ON endpoints(last_seen_at);
CREATE INDEX idx_endpoints_tags ON endpoints USING GIN(tags);

-- ============================================================================
-- POLICIES
-- ============================================================================

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL, -- compliance, custom, baseline
    compliance_framework VARCHAR(100), -- CIS, NIST_800_53, SOC2, PCI_DSS, ISO_27001
    rules JSONB NOT NULL, -- array of rule definitions
    remediation_mode VARCHAR(50) DEFAULT 'manual', -- manual, automatic, notify
    is_active BOOLEAN DEFAULT TRUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT valid_policy_type CHECK (policy_type IN ('compliance', 'custom', 'baseline')),
    CONSTRAINT valid_remediation CHECK (remediation_mode IN ('manual', 'automatic', 'notify'))
);

CREATE INDEX idx_policies_org ON policies(organization_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_policies_framework ON policies(compliance_framework) WHERE deleted_at IS NULL;
CREATE INDEX idx_policies_active ON policies(is_active) WHERE deleted_at IS NULL;

-- ============================================================================

CREATE TABLE policy_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CHECK ((endpoint_id IS NOT NULL AND team_id IS NULL) OR (endpoint_id IS NULL AND team_id IS NOT NULL)),
    UNIQUE(policy_id, endpoint_id),
    UNIQUE(policy_id, team_id)
);

CREATE INDEX idx_policy_assign_policy ON policy_assignments(policy_id);
CREATE INDEX idx_policy_assign_endpoint ON policy_assignments(endpoint_id);
CREATE INDEX idx_policy_assign_team ON policy_assignments(team_id);

-- ============================================================================
-- SCANS & FINDINGS (Time-series optimized)
-- ============================================================================

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    scan_type VARCHAR(50) NOT NULL, -- scheduled, manual, policy_check, incident_response
    status VARCHAR(50) NOT NULL DEFAULT 'running', -- running, completed, failed, cancelled
    triggered_by UUID REFERENCES users(id) ON DELETE SET NULL, -- null if automated
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    passed_count INTEGER DEFAULT 0,
    scan_metadata JSONB DEFAULT '{}',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_scan_type CHECK (scan_type IN ('scheduled', 'manual', 'policy_check', 'incident_response')),
    CONSTRAINT valid_status CHECK (status IN ('running', 'completed', 'failed', 'cancelled'))
);

CREATE INDEX idx_scans_org ON scans(organization_id);
CREATE INDEX idx_scans_endpoint ON scans(endpoint_id);
CREATE INDEX idx_scans_started ON scans(started_at DESC);
CREATE INDEX idx_scans_status ON scans(status);

-- ============================================================================

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,

    -- Finding details
    category VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,

    -- Current vs expected
    current_value TEXT,
    expected_value TEXT,

    -- Compliance mapping
    cis_benchmark VARCHAR(50),
    nist_control VARCHAR(50),
    compliance_frameworks JSONB DEFAULT '[]',

    -- Status
    passed BOOLEAN NOT NULL,
    remediation_script TEXT,
    remediation_status VARCHAR(50) DEFAULT 'pending', -- pending, applied, failed, skipped
    remediated_at TIMESTAMPTZ,
    remediated_by UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Context
    log_context TEXT,

    -- Deduplication
    finding_hash VARCHAR(64), -- SHA256 of (endpoint_id + category + name + current_value)
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT valid_severity CHECK (severity IN ('log-only', 'low', 'med', 'high', 'very-high')),
    CONSTRAINT valid_remediation CHECK (remediation_status IN ('pending', 'applied', 'failed', 'skipped'))
);

CREATE INDEX idx_findings_org ON findings(organization_id);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_endpoint ON findings(endpoint_id);
CREATE INDEX idx_findings_severity ON findings(severity) WHERE NOT passed;
CREATE INDEX idx_findings_hash ON findings(finding_hash);
CREATE INDEX idx_findings_first_seen ON findings(first_seen_at DESC);
CREATE INDEX idx_findings_frameworks ON findings USING GIN(compliance_frameworks);

-- ============================================================================
-- AUDIT LOGGING (Immutable, append-only)
-- ============================================================================

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE SET NULL,

    action VARCHAR(100) NOT NULL, -- login, logout, scan_triggered, policy_created, finding_remediated, etc.
    resource_type VARCHAR(50), -- user, endpoint, policy, scan, finding
    resource_id UUID,

    ip_address INET,
    user_agent TEXT,

    details JSONB DEFAULT '{}',

    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);
CREATE INDEX idx_audit_action ON audit_logs(action);

-- Prevent updates/deletes on audit logs
CREATE RULE audit_logs_no_update AS ON UPDATE TO audit_logs DO INSTEAD NOTHING;
CREATE RULE audit_logs_no_delete AS ON DELETE TO audit_logs DO INSTEAD NOTHING;

-- ============================================================================
-- BASELINES (for drift detection)
-- ============================================================================

CREATE TABLE baselines (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES endpoints(id) ON DELETE CASCADE,
    team_id UUID REFERENCES teams(id) ON DELETE CASCADE,

    name VARCHAR(255) NOT NULL,
    description TEXT,

    baseline_data JSONB NOT NULL, -- SecurityState JSON

    is_active BOOLEAN DEFAULT FALSE,

    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK ((endpoint_id IS NOT NULL AND team_id IS NULL) OR (endpoint_id IS NULL AND team_id IS NOT NULL))
);

CREATE INDEX idx_baselines_org ON baselines(organization_id);
CREATE INDEX idx_baselines_endpoint ON baselines(endpoint_id);
CREATE INDEX idx_baselines_team ON baselines(team_id);
CREATE INDEX idx_baselines_active ON baselines(is_active);

-- ============================================================================
-- WEBHOOKS
-- ============================================================================

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    name VARCHAR(255) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    secret VARCHAR(255), -- for HMAC signature verification

    events JSONB NOT NULL DEFAULT '[]', -- ["scan.completed", "finding.critical", "remediation.failed"]

    is_active BOOLEAN DEFAULT TRUE,

    headers JSONB DEFAULT '{}', -- custom HTTP headers

    retry_count INTEGER DEFAULT 3,
    timeout_seconds INTEGER DEFAULT 30,

    last_triggered_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_failure_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_org ON webhooks(organization_id);
CREATE INDEX idx_webhooks_active ON webhooks(is_active);

-- ============================================================================
-- LICENSES
-- ============================================================================

CREATE TABLE license_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    date DATE NOT NULL,

    active_endpoints INTEGER NOT NULL DEFAULT 0,
    scans_performed INTEGER NOT NULL DEFAULT 0,
    api_calls INTEGER NOT NULL DEFAULT 0,

    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(organization_id, date)
);

CREATE INDEX idx_license_usage_org_date ON license_usage(organization_id, date DESC);

-- ============================================================================
-- MIGRATIONS TRACKING
-- ============================================================================

CREATE TABLE schema_migrations (
    version VARCHAR(50) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) for multi-tenancy
-- ============================================================================

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE baselines ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;

-- Example RLS policy (apply similar policies for all tables)
CREATE POLICY org_isolation ON organizations
    USING (id = current_setting('app.current_organization_id')::UUID);

CREATE POLICY org_isolation_teams ON teams
    USING (organization_id = current_setting('app.current_organization_id')::UUID);

-- etc. for all multi-tenant tables

-- ============================================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_teams_updated_at BEFORE UPDATE ON teams
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_endpoints_updated_at BEFORE UPDATE ON endpoints
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policies_updated_at BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
```

---

### 2.3 API Architecture

#### 2.3.1 REST API Design (OpenAPI 3.0)

**Base URL:** `https://api.aftersec.com/v1`

**Authentication:** Bearer token (JWT) in `Authorization` header

**Core Endpoints:**

```
/v1/organizations:
  GET:    List organizations (admin only)
  POST:   Create organization (admin only)

/v1/organizations/{orgId}:
  GET:    Get organization details
  PATCH:  Update organization
  DELETE: Delete organization (soft delete)

/v1/organizations/{orgId}/teams:
  GET:    List teams
  POST:   Create team

/v1/organizations/{orgId}/users:
  GET:    List users
  POST:   Invite user

/v1/organizations/{orgId}/endpoints:
  GET:    List endpoints
    Query params: ?team_id=, ?status=, ?platform=, ?tags=, ?page=, ?limit=
  POST:   Enroll new endpoint (returns enrollment token)

/v1/endpoints/{endpointId}:
  GET:    Get endpoint details
  PATCH:  Update endpoint metadata
  DELETE: Revoke endpoint

/v1/endpoints/{endpointId}/scans:
  GET:    List scans for endpoint
  POST:   Trigger manual scan

/v1/scans/{scanId}:
  GET:    Get scan details and findings
  DELETE: Cancel running scan

/v1/scans/{scanId}/findings:
  GET:    List findings for scan
    Query params: ?severity=, ?passed=false, ?category=, ?page=, ?limit=

/v1/findings/{findingId}:
  GET:    Get finding details
  POST:   /remediate - Execute remediation script

/v1/policies:
  GET:    List policies
  POST:   Create policy

/v1/policies/{policyId}:
  GET:    Get policy details
  PATCH:  Update policy
  DELETE: Delete policy

/v1/policies/{policyId}/assignments:
  GET:    List policy assignments
  POST:   Assign policy to endpoints/teams
  DELETE: Remove policy assignment

/v1/baselines:
  GET:    List baselines
  POST:   Create baseline from scan

/v1/baselines/{baselineId}:
  GET:    Get baseline
  POST:   /activate - Set as active baseline
  POST:   /compare - Compare endpoint state against baseline

/v1/compliance/frameworks:
  GET:    List supported compliance frameworks

/v1/compliance/reports/{framework}:
  GET:    Generate compliance report
    Query params: ?endpoint_id=, ?team_id=, ?format=pdf|json|csv

/v1/webhooks:
  GET:    List webhooks
  POST:   Create webhook

/v1/webhooks/{webhookId}:
  GET:    Get webhook details
  PATCH:  Update webhook
  DELETE: Delete webhook
  POST:   /test - Send test payload

/v1/audit-logs:
  GET:    Query audit logs
    Query params: ?user_id=, ?action=, ?start_date=, ?end_date=, ?page=, ?limit=

/v1/users/me:
  GET:    Get current user profile
  PATCH:  Update profile

/v1/users/me/api-keys:
  GET:    List API keys
  POST:   Generate new API key
  DELETE: Revoke API key

/v1/health:
  GET:    Health check

/v1/metrics:
  GET:    Prometheus metrics endpoint
```

**Response Format:**

```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "page": 1,
    "limit": 50,
    "total": 250,
    "next_cursor": "eyJpZCI6IjEyMyJ9"
  },
  "timestamp": "2026-03-24T10:30:00Z"
}
```

**Error Format:**

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid endpoint status",
    "details": {
      "field": "status",
      "expected": "pending|active|inactive|revoked"
    }
  },
  "timestamp": "2026-03-24T10:30:00Z"
}
```

---

## 3. TECHNOLOGY STACK RECOMMENDATIONS

### 3.1 Backend Services

**Language:** Go 1.22+ (existing codebase, excellent concurrency, performance)

**Web Framework:**
- **Gin** (REST API) - Fast, lightweight, middleware-rich
- Alternative: **Echo** or **Fiber**

**GraphQL:**
- **gqlgen** - Code-first GraphQL for Go

**gRPC:**
- **grpc-go** with Protocol Buffers 3

**Database:**
- **Primary:** PostgreSQL 15+ with TimescaleDB extension for time-series data
- **Migration Tool:** golang-migrate or Atlas
- **ORM/Query Builder:** sqlc (type-safe SQL) or ent (graph-based ORM)

**Caching:**
- **Redis 7+** (session storage, rate limiting, API response cache)

**Message Queue:**
- **Option 1:** RabbitMQ (feature-rich, mature)
- **Option 2:** AWS SQS + SNS (cloud-native, managed)
- **Option 3:** NATS (lightweight, high-performance)

**Authentication:**
- **JWT:** github.com/golang-jwt/jwt
- **OAuth2:** golang.org/x/oauth2
- **SAML:** github.com/crewjam/saml

**RBAC:**
- **Casbin** - Authorization library supporting RBAC, ABAC

---

### 3.2 Frontend

**Framework:** **Next.js 14+** (React)
- Server-side rendering for SEO
- Built-in API routes
- Excellent TypeScript support
- Strong ecosystem

**Alternative:** Nuxt 3 (Vue) if team prefers Vue

**UI Library:**
- **Tailwind CSS** + **shadcn/ui** (modern, accessible components)
- **Alternative:** Material-UI, Ant Design, Chakra UI

**State Management:**
- **TanStack Query** (React Query) for server state
- **Zustand** for client state (lightweight)

**GraphQL Client:**
- **Apollo Client** or **urql**

**Charts/Visualization:**
- **Recharts** or **Apache ECharts**

**Real-time:**
- **WebSocket** (native) or **Socket.io**

---

### 3.3 Observability

**Metrics:**
- **Prometheus** (collection)
- **Grafana** (visualization)
- **Go Instrumentation:** github.com/prometheus/client_golang

**Logging:**
- **Structured Logging:** go.uber.org/zap or github.com/rs/zerolog
- **Centralized:** Loki (Grafana Loki) + Promtail
- **Alternative:** ELK Stack (Elasticsearch, Logstash, Kibana)

**Distributed Tracing:**
- **Jaeger** or **Tempo**
- **Instrumentation:** OpenTelemetry Go SDK

**APM (optional):**
- **DataDog**
- **New Relic**
- **Elastic APM**

---

### 3.4 Infrastructure

**Containerization:**
- **Docker** with multi-stage builds
- **Base Images:** alpine or distroless for security

**Orchestration:**
- **Kubernetes** (primary)
- **Helm** for package management

**CI/CD:**
- **GitHub Actions** (first choice for GitHub repos)
- **GitLab CI** or **Jenkins** for self-hosted

**IaC (Infrastructure as Code):**
- **Terraform** for cloud resources (AWS, GCP, Azure)
- **Pulumi** (alternative, uses real programming languages)

**Configuration Management:**
- **Ansible** for agent installation on endpoints

**Secrets Management:**
- **HashiCorp Vault**
- **AWS Secrets Manager** (cloud deployments)
- **Sealed Secrets** (Kubernetes)

---

### 3.5 Testing

**Unit Testing:**
- **testing** (Go standard library)
- **testify** (assertions, mocks)

**Integration Testing:**
- **testcontainers-go** (Docker-based integration tests)

**E2E Testing:**
- **Playwright** (frontend)
- **Postman/Newman** (API)

**Load Testing:**
- **k6** (Grafana k6)
- **Locust**

**Security Testing:**
- **SAST:** gosec, staticcheck
- **DAST:** OWASP ZAP
- **Dependency Scanning:** Snyk, GitHub Dependabot

---

## 4. IMPLEMENTATION ROADMAP

### Phase 1: Foundation (Months 1-4)

**Objective:** Establish enterprise-grade data persistence, authentication, and core API

#### Deliverables:

1. **Database Layer**
   - PostgreSQL schema implementation
   - Migration system setup
   - Repository pattern implementation
   - Row-level security for multi-tenancy

   **Files to Create:**
   - `migrations/000001_initial_schema.up.sql`
   - `pkg/database/client.go`
   - `pkg/database/migrations.go`
   - `pkg/repository/organizations.go`
   - `pkg/repository/users.go`
   - `pkg/repository/endpoints.go`
   - `pkg/repository/scans.go`
   - `pkg/repository/findings.go`

2. **Authentication System**
   - JWT-based authentication
   - User registration/login
   - API key management
   - Password reset flow

   **Files to Create:**
   - `pkg/auth/jwt.go`
   - `pkg/auth/middleware.go`
   - `pkg/auth/password.go`
   - `pkg/auth/apikeys.go`

3. **Authorization (RBAC)**
   - Role definitions
   - Permission checking middleware
   - Casbin integration

   **Files to Create:**
   - `pkg/authz/roles.go`
   - `pkg/authz/permissions.go`
   - `pkg/authz/casbin_adapter.go`
   - `configs/rbac_model.conf`

4. **Core REST API v2**
   - Gin framework setup
   - Organization endpoints
   - User management endpoints
   - Endpoint enrollment
   - Health/ready checks

   **Files to Modify:**
   - `pkg/api/server.go` (complete rewrite)

   **Files to Create:**
   - `pkg/api/v2/router.go`
   - `pkg/api/v2/handlers/organizations.go`
   - `pkg/api/v2/handlers/users.go`
   - `pkg/api/v2/handlers/endpoints.go`
   - `pkg/api/v2/handlers/auth.go`
   - `pkg/api/v2/middleware/cors.go`
   - `pkg/api/v2/middleware/ratelimit.go`
   - `pkg/api/v2/middleware/logging.go`
   - `pkg/api/v2/middleware/recovery.go`

5. **Data Migration from File Storage**
   - Migration tool to import existing `~/.aftersec/` data
   - Backward compatibility layer

   **Files to Create:**
   - `cmd/migrate-storage/main.go`
   - `pkg/migration/legacy.go`

6. **OpenAPI Documentation**
   - Auto-generated from code annotations

   **Files to Create:**
   - `api/openapi.yaml`
   - `docs/api/v2/README.md`

#### Critical Path:
Database schema → Repository layer → Auth layer → API handlers → Testing → Documentation

---

### Phase 2: Core Features (Months 5-9)

**Objective:** Build enterprise web UI, enhanced daemon, and central management

#### Deliverables:

1. **Web Dashboard (Next.js)**
   - Login/registration
   - Organization dashboard
   - Endpoint inventory
   - Scan history viewer
   - Finding explorer with filters
   - Real-time updates (WebSocket)

   **Directory Structure:**
   ```
   web/
   ├── public/
   ├── src/
   │   ├── app/
   │   │   ├── (auth)/
   │   │   │   ├── login/
   │   │   │   └── register/
   │   │   ├── (dashboard)/
   │   │   │   ├── endpoints/
   │   │   │   ├── scans/
   │   │   │   ├── findings/
   │   │   │   ├── policies/
   │   │   │   └── settings/
   │   │   └── layout.tsx
   │   ├── components/
   │   │   ├── ui/ (shadcn components)
   │   │   ├── charts/
   │   │   └── tables/
   │   ├── lib/
   │   │   ├── api.ts
   │   │   ├── auth.ts
   │   │   └── utils.ts
   │   └── hooks/
   ├── package.json
   └── tsconfig.json
   ```

2. **Enhanced Background Daemon**
   - gRPC server for agent communication
   - Policy distribution
   - Intelligent scheduling
   - Resource limiting
   - Graceful shutdown

   **Files to Modify:**
   - `cmd/aftersecd/main.go` (major refactor)

   **Files to Create:**
   - `pkg/daemon/server.go`
   - `pkg/daemon/grpc_server.go`
   - `pkg/daemon/scheduler.go`
   - `pkg/daemon/policy_sync.go`
   - `pkg/daemon/heartbeat.go`
   - `api/proto/agent.proto`

3. **Policy Management**
   - Policy CRUD operations
   - Policy assignment to endpoints/teams
   - Built-in compliance policies (CIS, NIST)

   **Files to Create:**
   - `pkg/policy/engine.go`
   - `pkg/policy/evaluator.go`
   - `pkg/policy/templates/cis_macos.yaml`
   - `pkg/policy/templates/nist_800_53.yaml`

4. **Scan Orchestration**
   - Centralized scan triggering
   - Scan queue management (RabbitMQ/SQS)
   - Progress tracking
   - Result aggregation

   **Files to Create:**
   - `pkg/orchestrator/scan_manager.go`
   - `pkg/orchestrator/queue.go`
   - `pkg/orchestrator/worker.go`

5. **Baseline & Drift Detection**
   - Baseline creation from scans
   - Automated drift detection
   - Alerting on drift

   **Files to Create:**
   - `pkg/baseline/manager.go`
   - `pkg/baseline/comparator.go`
   - `pkg/baseline/drift_detector.go`

6. **Remediation Engine**
   - Approval workflows
   - Batch remediation
   - Rollback capability

   **Files to Modify:**
   - `pkg/core/remediate.go` (enhance)

   **Files to Create:**
   - `pkg/remediation/workflow.go`
   - `pkg/remediation/executor.go`
   - `pkg/remediation/approval.go`

#### Critical Path:
Web UI → gRPC daemon → Policy engine → Scan orchestration → Baseline management

---

### Phase 3: Enterprise Features (Months 10-14)

**Objective:** Add licensing, SSO, RBAC enhancements, and compliance features

#### Deliverables:

1. **Licensing System**
   - License validation server
   - Seat tracking
   - Feature gates
   - Trial management
   - Offline licensing

   **Files to Create:**
   - `pkg/licensing/validator.go`
   - `pkg/licensing/features.go`
   - `pkg/licensing/offline.go`
   - `pkg/licensing/usage_tracker.go`
   - `cmd/license-server/main.go`

2. **SSO Integration**
   - SAML 2.0 provider
   - OAuth2 provider (Google, Microsoft, Okta)
   - LDAP/Active Directory

   **Files to Create:**
   - `pkg/auth/sso/saml.go`
   - `pkg/auth/sso/oauth2.go`
   - `pkg/auth/sso/ldap.go`
   - `pkg/auth/sso/providers.go`

3. **Enhanced RBAC**
   - Custom role creation
   - Granular permissions
   - Team-based access control

   **Files to Modify:**
   - `pkg/authz/*` (enhance)

   **Files to Create:**
   - `pkg/authz/custom_roles.go`
   - `pkg/authz/team_permissions.go`

4. **Compliance Reporting**
   - CIS Benchmark reports
   - NIST 800-53 mapping
   - SOC2 evidence collection
   - PCI-DSS reports
   - PDF/Excel export

   **Files to Create:**
   - `pkg/compliance/cis.go`
   - `pkg/compliance/nist.go`
   - `pkg/compliance/soc2.go`
   - `pkg/compliance/pci_dss.go`
   - `pkg/compliance/reporter.go`
   - `pkg/compliance/export/pdf.go`
   - `pkg/compliance/export/excel.go`

5. **Webhook System**
   - Event dispatcher
   - Retry logic
   - HMAC signature verification
   - Webhook templates

   **Files to Create:**
   - `pkg/webhooks/dispatcher.go`
   - `pkg/webhooks/retry.go`
   - `pkg/webhooks/signature.go`
   - `pkg/webhooks/events.go`

6. **Audit Logging**
   - Comprehensive action logging
   - Immutable audit trail
   - Compliance-ready exports

   **Files to Create:**
   - `pkg/audit/logger.go`
   - `pkg/audit/middleware.go`
   - `pkg/audit/export.go`

#### Critical Path:
Licensing → SSO → Compliance → Webhooks → Audit logging

---

### Phase 4: Integrations & Automation (Months 15-18)

**Objective:** Build integrations, SDKs, and automation tools

#### Deliverables:

1. **GraphQL API**
   - Full schema implementation
   - Query optimization
   - Subscriptions for real-time

   **Files to Create:**
   - `pkg/api/graphql/schema.graphql`
   - `pkg/api/graphql/resolvers/`
   - `pkg/api/graphql/server.go`

2. **Client SDKs**
   - Python SDK
   - JavaScript/TypeScript SDK
   - Ruby SDK
   - Go SDK (enhance existing)

   **Directory Structure:**
   ```
   sdks/
   ├── python/
   │   ├── aftersec/
   │   │   ├── client.py
   │   │   ├── resources/
   │   │   └── models/
   │   ├── setup.py
   │   └── README.md
   ├── javascript/
   │   ├── src/
   │   │   ├── client.ts
   │   │   ├── resources/
   │   │   └── models/
   │   ├── package.json
   │   └── README.md
   └── ruby/
       ├── lib/aftersec/
       ├── aftersec.gemspec
       └── README.md
   ```

3. **Terraform Provider**
   - Resource definitions
   - Data sources
   - Examples

   **Files to Create:**
   - `terraform-provider-aftersec/provider.go`
   - `terraform-provider-aftersec/resource_policy.go`
   - `terraform-provider-aftersec/resource_endpoint.go`

4. **Ansible Modules**
   - aftersec_scan module
   - aftersec_policy module
   - aftersec_baseline module

   **Files to Create:**
   - `ansible/library/aftersec_scan.py`
   - `ansible/library/aftersec_policy.py`
   - `ansible/library/aftersec_baseline.py`

5. **CI/CD Plugins**
   - GitHub Actions
   - GitLab CI
   - Jenkins plugin

   **Files to Create:**
   - `github-actions/scan/action.yml`
   - `gitlab-ci/aftersec-scan.yml`

6. **SIEM Integrations**
   - Splunk app
   - Elastic integration
   - AWS Security Hub

   **Files to Create:**
   - `pkg/integrations/splunk/forwarder.go`
   - `pkg/integrations/elastic/shipper.go`
   - `pkg/integrations/aws_security_hub/publisher.go`

#### Critical Path:
GraphQL → Python SDK → Terraform → Ansible → CI/CD plugins

---

### Phase 5: Cloud & Marketplace (Months 19-24)

**Objective:** Prepare for cloud deployment and marketplace listings

#### Deliverables:

1. **Containerization**
   - Production-grade Dockerfiles
   - Multi-arch builds (amd64, arm64)
   - Security scanning

   **Files to Create:**
   - `Dockerfile.api`
   - `Dockerfile.daemon`
   - `Dockerfile.worker`
   - `.dockerignore`

2. **Kubernetes Manifests**
   - Helm charts
   - Operators (optional)
   - Service mesh integration (Istio)

   **Files to Create:**
   - `charts/aftersec/Chart.yaml`
   - `charts/aftersec/values.yaml`
   - `charts/aftersec/templates/`

3. **Terraform Modules**
   - AWS deployment
   - GCP deployment
   - Azure deployment

   **Files to Create:**
   - `terraform/aws/main.tf`
   - `terraform/gcp/main.tf`
   - `terraform/azure/main.tf`

4. **Package Management**
   - Homebrew formula
   - APT repository
   - YUM repository
   - Windows MSI installer

   **Files to Create:**
   - `packaging/homebrew/aftersec.rb`
   - `packaging/debian/control`
   - `packaging/rpm/aftersec.spec`
   - `packaging/windows/installer.wxs`

5. **Cloud Marketplace Listings**
   - AWS Marketplace AMI
   - Azure Marketplace VM
   - GCP Marketplace image

   **Documentation:**
   - `docs/marketplace/aws.md`
   - `docs/marketplace/azure.md`
   - `docs/marketplace/gcp.md`

6. **SaaS Platform**
   - Multi-region deployment
   - Data residency compliance
   - Backup/restore procedures

   **Files to Create:**
   - `deployments/production/us-east-1/`
   - `deployments/production/eu-west-1/`
   - `pkg/backup/manager.go`

#### Critical Path:
Docker → Kubernetes → Terraform → Package management → Marketplace

---

## 5. FILE STRUCTURE REORGANIZATION

### 5.1 Recommended Monorepo Structure

```
aftersec/
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── release.yml
│       └── security-scan.yml
│
├── api/
│   ├── openapi/
│   │   └── v2.yaml
│   └── proto/
│       ├── agent.proto
│       ├── common.proto
│       └── events.proto
│
├── charts/
│   └── aftersec/
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│
├── cmd/
│   ├── aftersec/              # CLI tool
│   │   └── main.go
│   ├── aftersec-gui/           # Desktop GUI
│   │   └── main.go
│   ├── aftersecd/              # Agent daemon
│   │   └── main.go
│   ├── aftersec-server/        # Central server (API + gRPC)
│   │   └── main.go
│   ├── aftersec-worker/        # Background worker (queue processor)
│   │   └── main.go
│   ├── migrate-storage/        # Data migration tool
│   │   └── main.go
│   └── license-server/         # License validation server
│       └── main.go
│
├── configs/
│   ├── config.yaml.example
│   ├── rbac_model.conf
│   └── policy_templates/
│
├── deployments/
│   ├── development/
│   ├── staging/
│   └── production/
│
├── docs/
│   ├── api/
│   ├── architecture/
│   ├── deployment/
│   ├── user-guide/
│   └── marketplace/
│
├── migrations/
│   ├── 000001_initial_schema.up.sql
│   ├── 000001_initial_schema.down.sql
│   ├── 000002_add_teams.up.sql
│   └── 000002_add_teams.down.sql
│
├── pkg/
│   ├── api/
│   │   ├── v1/                 # Legacy API (deprecated)
│   │   ├── v2/                 # REST API v2
│   │   │   ├── router.go
│   │   │   ├── handlers/
│   │   │   └── middleware/
│   │   ├── graphql/            # GraphQL API
│   │   │   ├── schema.graphql
│   │   │   ├── resolvers/
│   │   │   └── server.go
│   │   └── grpc/               # gRPC services
│   │       ├── agent/
│   │       └── internal/
│   ├── audit/
│   │   ├── logger.go
│   │   └── middleware.go
│   ├── auth/
│   │   ├── jwt.go
│   │   ├── middleware.go
│   │   ├── password.go
│   │   └── sso/
│   │       ├── saml.go
│   │       ├── oauth2.go
│   │       └── ldap.go
│   ├── authz/
│   │   ├── casbin_adapter.go
│   │   ├── permissions.go
│   │   └── roles.go
│   ├── baseline/
│   │   ├── manager.go
│   │   ├── comparator.go
│   │   └── drift_detector.go
│   ├── compliance/
│   │   ├── cis.go
│   │   ├── nist.go
│   │   ├── soc2.go
│   │   ├── reporter.go
│   │   └── export/
│   │       ├── pdf.go
│   │       └── excel.go
│   ├── core/
│   │   ├── config.go
│   │   ├── diff.go
│   │   ├── remediate.go
│   │   └── state.go
│   ├── daemon/
│   │   ├── server.go
│   │   ├── grpc_server.go
│   │   ├── scheduler.go
│   │   ├── policy_sync.go
│   │   └── heartbeat.go
│   ├── database/
│   │   ├── client.go
│   │   ├── migrations.go
│   │   └── connection_pool.go
│   ├── editor/
│   │   └── manager.go
│   ├── forensics/
│   │   ├── memory.go
│   │   ├── behavior.go
│   │   ├── persistence.go
│   │   ├── syscall.go
│   │   ├── threats.go
│   │   └── process_darwin.go
│   ├── integrations/
│   │   ├── splunk/
│   │   ├── elastic/
│   │   └── aws_security_hub/
│   ├── licensing/
│   │   ├── validator.go
│   │   ├── features.go
│   │   └── offline.go
│   ├── orchestrator/
│   │   ├── scan_manager.go
│   │   ├── queue.go
│   │   └── worker.go
│   ├── plugins/
│   │   └── starlark.go
│   ├── policy/
│   │   ├── engine.go
│   │   ├── evaluator.go
│   │   └── templates/
│   ├── remediation/
│   │   ├── workflow.go
│   │   ├── executor.go
│   │   └── approval.go
│   ├── repository/
│   │   ├── organizations.go
│   │   ├── users.go
│   │   ├── endpoints.go
│   │   ├── scans.go
│   │   └── findings.go
│   ├── scanners/
│   │   ├── macos.go
│   │   ├── export.go
│   │   ├── secrets.go
│   │   └── vuln.go
│   ├── storage/
│   │   └── manager.go         # Legacy, kept for migration
│   ├── tuning/
│   │   ├── startup.go
│   │   ├── finder.go
│   │   ├── tools.go
│   │   └── sysctl.go
│   └── webhooks/
│       ├── dispatcher.go
│       ├── retry.go
│       └── signature.go
│
├── sdks/
│   ├── go/
│   │   └── afterseclib/
│   ├── python/
│   │   └── aftersec/
│   ├── javascript/
│   │   └── src/
│   └── ruby/
│       └── lib/
│
├── scripts/
│   ├── build.sh
│   ├── test.sh
│   ├── docker-build.sh
│   └── generate-certs.sh
│
├── terraform/
│   ├── aws/
│   ├── gcp/
│   └── azure/
│
├── tests/
│   ├── integration/
│   ├── e2e/
│   └── load/
│
├── web/
│   ├── public/
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── lib/
│   │   └── hooks/
│   ├── package.json
│   ├── next.config.js
│   └── tsconfig.json
│
├── .dockerignore
├── .gitignore
├── Dockerfile.api
├── Dockerfile.daemon
├── Dockerfile.worker
├── LICENSE
├── Makefile
├── README.md
└── go.mod
```

---

## 6. SCALABILITY PLAN

### 6.1 Handling 10,000+ Concurrent Endpoints

**Database Optimization:**

1. **Connection Pooling:**
   - PgBouncer in transaction mode
   - Pool size: `(core_count * 2) + effective_spindle_count`
   - Typical: 100-200 connections per API instance

2. **Read Replicas:**
   - 3-5 read replicas for horizontal scaling
   - Route read queries to replicas
   - Primary for writes only

3. **Partitioning:**
   - Partition `scans` table by month (keep 12 months hot, archive rest)
   - Partition `findings` table by month
   - Partition `audit_logs` by month
   - Use TimescaleDB hypertables for automatic partitioning

4. **Indexing Strategy:**
   - Composite indexes on high-cardinality queries
   - Partial indexes for filtered queries
   - GIN indexes for JSONB columns
   - Regular VACUUM ANALYZE (autovacuum tuning)

5. **Query Optimization:**
   - Use prepared statements
   - Batch inserts for findings (use COPY or multi-row INSERT)
   - Limit result sets with cursor-based pagination
   - Materialized views for complex reports

**Caching Strategy:**

1. **Redis Layers:**
   - L1: API response cache (5-minute TTL)
   - L2: Session storage (JWT claims)
   - L3: Rate limiting counters
   - L4: Aggregation cache (endpoint counts, scan summaries)

2. **Cache Invalidation:**
   - Event-driven invalidation on write operations
   - Tag-based invalidation (by org_id, endpoint_id)

**API Layer:**

1. **Horizontal Scaling:**
   - Stateless API servers
   - Kubernetes HPA: 5-50 pods based on CPU/memory
   - Load balancing via Kubernetes Service or AWS ALB

2. **Rate Limiting:**
   - Per-organization limits: 1000 req/min
   - Per-user limits: 100 req/min
   - Burst allowance: 50 requests
   - Implemented in Redis with sliding window

3. **Request Optimization:**
   - GraphQL query complexity limits
   - Field-level authorization
   - DataLoader for N+1 prevention

**Message Queue:**

1. **Queue Design:**
   - High-priority queue: Manual scans, incident response
   - Normal queue: Scheduled scans
   - Low-priority queue: Report generation
   - Dead letter queue: Failed jobs

2. **Worker Scaling:**
   - Auto-scale workers based on queue depth
   - 1 worker per 100 queued jobs
   - Max concurrency: 10 scans per worker

**Agent Communication:**

1. **gRPC Multiplexing:**
   - Single gRPC connection per agent (persistent)
   - HTTP/2 multiplexing for efficiency
   - Connection pooling on server side

2. **Heartbeat Optimization:**
   - Adaptive intervals: 30s (healthy) to 5m (stable)
   - Batch heartbeat processing (every 10s)

### 6.2 Multi-Region Deployment

**Architecture:**

```
Region: us-east-1 (Primary)
├── API Cluster (3 AZs)
├── PostgreSQL RDS (Multi-AZ, read replicas)
├── Redis ElastiCache (Multi-AZ)
├── RabbitMQ (Clustered)
└── S3 (cross-region replication)

Region: eu-west-1 (Secondary)
├── API Cluster (3 AZs)
├── PostgreSQL RDS (Read replicas from us-east-1)
├── Redis ElastiCache (Multi-AZ)
├── RabbitMQ (Clustered)
└── S3 (replica)

Global:
├── Route 53 (latency-based routing)
├── CloudFront (API acceleration, static assets)
└── DynamoDB Global Tables (session storage, optional)
```

**Data Replication:**

- Streaming replication for PostgreSQL (async to EU)
- S3 cross-region replication for large exports
- Redis Sentinel for failover

**Disaster Recovery:**

- RTO: 15 minutes (automated failover)
- RPO: 5 minutes (max data loss)
- Daily backups retained for 30 days
- Monthly backups retained for 12 months

---

## 7. MIGRATION STRATEGY

### 7.1 Upgrading Existing Deployments

**Backward Compatibility:**

1. **API Versioning:**
   - Keep `/api/v1` endpoints operational for 12 months post-v2 launch
   - Deprecation warnings in response headers
   - Migration guide in documentation

2. **Data Migration:**
   - Tool to import `~/.aftersec/` JSON files into PostgreSQL
   - Preserve all historical scans and findings
   - Generate organization/endpoint records from legacy data

3. **CLI Compatibility:**
   - New CLI supports both legacy file storage and new API
   - Auto-detect mode based on config
   - Gradual migration with `aftersec migrate` command

**Migration Process:**

```bash
# Step 1: Backup existing data
aftersec backup --output /tmp/aftersec-backup.tar.gz

# Step 2: Install new version
brew upgrade aftersec

# Step 3: Initialize database (first-time only)
aftersec-server init-db --config /etc/aftersec/config.yaml

# Step 4: Migrate data
aftersec migrate --from ~/.aftersec --to postgresql://...

# Step 5: Verify migration
aftersec verify-migration

# Step 6: Update daemon config to use new server
sudo systemctl edit aftersecd
# Change: AFTERSEC_MODE=standalone -> AFTERSEC_MODE=agent

# Step 7: Restart daemon
sudo systemctl restart aftersecd
```

---

## 8. TESTING STRATEGY

### 8.1 Test Pyramid

```
        /\
       /  \  E2E Tests (5%)
      /    \ - Playwright (web UI)
     /------\ - API integration tests
    /        \
   /  Integ.  \ Integration Tests (15%)
  /   Tests    \ - Database integration
 /--------------\ - gRPC tests
/                \ - Queue integration
/   Unit Tests    \ Unit Tests (80%)
--------------------
```

### 8.2 Unit Testing

**Coverage Target:** 80% minimum

**Framework:** Go testing + testify

**Example:**

```go
// pkg/repository/endpoints_test.go
package repository_test

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestEndpointRepository_Create(t *testing.T) {
    db := setupTestDB(t)
    defer teardownTestDB(t, db)

    repo := repository.NewEndpointRepository(db)

    endpoint := &models.Endpoint{
        OrganizationID: testOrgID,
        Hostname: "test-mac-01",
        Platform: "macos",
    }

    err := repo.Create(context.Background(), endpoint)
    require.NoError(t, err)
    assert.NotEmpty(t, endpoint.ID)

    // Verify in DB
    found, err := repo.GetByID(context.Background(), endpoint.ID)
    require.NoError(t, err)
    assert.Equal(t, "test-mac-01", found.Hostname)
}
```

### 8.3 Integration Testing

**Framework:** testcontainers-go

**Example:**

```go
// tests/integration/api_test.go
package integration_test

import (
    "testing"
    "github.com/testcontainers/testcontainers-go"
)

func TestAPIEndpoints_ListEndpoints(t *testing.T) {
    // Start PostgreSQL container
    pgContainer := startPostgresContainer(t)
    defer pgContainer.Terminate()

    // Start Redis container
    redisContainer := startRedisContainer(t)
    defer redisContainer.Terminate()

    // Start API server
    apiServer := startAPIServer(t, pgContainer, redisContainer)
    defer apiServer.Shutdown()

    // Test API
    client := newTestClient(apiServer.URL)
    resp, err := client.ListEndpoints(testOrgID)
    require.NoError(t, err)
    assert.NotNil(t, resp)
}
```

### 8.4 E2E Testing

**Framework:** Playwright (TypeScript)

**Example:**

```typescript
// web/tests/e2e/endpoints.spec.ts
import { test, expect } from '@playwright/test';

test('user can view endpoints', async ({ page }) => {
  // Login
  await page.goto('https://localhost:3000/login');
  await page.fill('[name=email]', 'test@example.com');
  await page.fill('[name=password]', 'password123');
  await page.click('button[type=submit]');

  // Navigate to endpoints
  await page.click('text=Endpoints');
  await expect(page).toHaveURL('/endpoints');

  // Verify table loads
  await expect(page.locator('table')).toBeVisible();
  await expect(page.locator('table tbody tr')).toHaveCount(5);
});
```

### 8.5 Load Testing

**Framework:** k6

**Example:**

```javascript
// tests/load/api_load.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 },  // Ramp up
    { duration: '5m', target: 100 },  // Sustained load
    { duration: '2m', target: 200 },  // Spike
    { duration: '5m', target: 200 },  // Sustained spike
    { duration: '2m', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% requests < 500ms
    http_req_failed: ['rate<0.01'],   // <1% errors
  },
};

export default function () {
  let res = http.get('https://api.aftersec.com/v1/endpoints', {
    headers: { 'Authorization': 'Bearer ' + __ENV.API_TOKEN },
  });

  check(res, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });

  sleep(1);
}
```

---

## 9. DOCUMENTATION REQUIREMENTS

### 9.1 Documentation Structure

```
docs/
├── README.md                    # Overview
├── getting-started/
│   ├── installation.md
│   ├── quickstart.md
│   └── concepts.md
├── user-guide/
│   ├── scanning.md
│   ├── policies.md
│   ├── baselines.md
│   ├── remediation.md
│   ├── compliance-reporting.md
│   └── webhooks.md
├── admin-guide/
│   ├── installation/
│   │   ├── kubernetes.md
│   │   ├── docker-compose.md
│   │   └── bare-metal.md
│   ├── configuration.md
│   ├── authentication/
│   │   ├── sso-saml.md
│   │   ├── sso-oauth2.md
│   │   └── ldap.md
│   ├── scaling.md
│   ├── backup-restore.md
│   └── monitoring.md
├── api/
│   ├── rest-api.md
│   ├── graphql-api.md
│   ├── authentication.md
│   ├── rate-limiting.md
│   └── webhooks.md
├── sdk/
│   ├── go.md
│   ├── python.md
│   ├── javascript.md
│   └── ruby.md
├── integrations/
│   ├── terraform.md
│   ├── ansible.md
│   ├── github-actions.md
│   ├── splunk.md
│   └── aws-security-hub.md
├── architecture/
│   ├── overview.md
│   ├── database-schema.md
│   ├── security.md
│   └── multi-tenancy.md
├── development/
│   ├── contributing.md
│   ├── building.md
│   ├── testing.md
│   └── plugin-development.md
└── compliance/
    ├── cis-benchmarks.md
    ├── nist-800-53.md
    ├── soc2.md
    └── pci-dss.md
```

### 9.2 Interactive Documentation

- **OpenAPI/Swagger UI** for REST API
- **GraphQL Playground** for GraphQL API
- **Runnable code examples** (CodeSandbox, Replit)
- **Video tutorials** for common tasks
- **Architecture diagrams** (draw.io, Mermaid)

---

## 10. RISK ASSESSMENT

### 10.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Database migration failures** | Medium | High | Comprehensive testing, rollback procedures, data validation tools |
| **API breaking changes** | Medium | High | Strict versioning, deprecation policy, backward compatibility layer |
| **Performance degradation at scale** | Medium | High | Load testing early, horizontal scaling design, caching strategy |
| **Security vulnerabilities** | Low | Critical | Security audits, penetration testing, bug bounty program |
| **Third-party dependency issues** | Medium | Medium | Vendor lock-in avoidance, abstraction layers, dependency monitoring |
| **Data loss during migration** | Low | Critical | Multiple backups, test migrations, verification scripts |
| **Agent compatibility issues** | High | Medium | Extensive platform testing, gradual rollout, version compatibility matrix |
| **License server downtime** | Low | High | Offline licensing mode, failover redundancy, status monitoring |

### 10.2 Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Slow enterprise adoption** | Medium | High | Early customer pilots, proof-of-value program, migration assistance |
| **Competitor feature parity** | High | Medium | Continuous innovation, unique differentiators (macOS focus, Starlark plugins) |
| **Regulatory compliance gaps** | Low | Critical | Legal review, compliance experts, audit trails |
| **Pricing model rejection** | Medium | Medium | Flexible licensing tiers, transparent pricing, trial programs |
| **Support burden increase** | High | Medium | Self-service docs, community forum, tiered support plans |

### 10.3 Operational Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| **Team skill gaps** | Medium | Medium | Training programs, expert consultation, phased hiring |
| **Timeline delays** | High | Medium | Agile methodology, iterative releases, buffer time |
| **Infrastructure costs** | Medium | Medium | Cost monitoring, reserved instances, right-sizing |
| **On-call burden** | Medium | Medium | Automated alerting, runbooks, SRE team |

---

## 11. SUCCESS METRICS

### 11.1 Technical KPIs

- **API Availability:** 99.9% uptime SLA
- **API Latency:** p95 < 200ms, p99 < 500ms
- **Database Query Time:** p95 < 50ms
- **Scan Completion:** 95% complete within 5 minutes
- **Agent Connectivity:** 99% of agents check-in within heartbeat interval
- **Error Rate:** < 0.1% of API requests
- **Test Coverage:** > 80% code coverage

### 11.2 Business KPIs

- **Customer Adoption:** 50+ enterprise customers in Year 1
- **Seat Growth:** 10,000+ managed endpoints in Year 1
- **API Usage:** 10M+ API calls/month
- **Customer Satisfaction:** NPS > 40
- **Support Ticket Resolution:** < 24 hours for P1, < 48 hours for P2

### 11.3 Compliance KPIs

- **Audit Readiness:** 100% audit trail coverage
- **Compliance Reports:** 90% of customers generate monthly reports
- **Remediation Rate:** 70% of critical findings remediated within 7 days
- **Baseline Drift Detection:** 95% accuracy

---

## 12. CONCLUSION

Transforming AfterSec from a single-user macOS security tool into an enterprise-grade Norton competitor is a substantial but achievable undertaking. The current codebase provides an excellent foundation with strong security primitives and innovative features like behavioral analysis and Starlark extensibility.

### 12.1 Critical Success Factors

1. **Database-first approach:** Migrating to PostgreSQL is the cornerstone of enterprise readiness
2. **API maturity:** REST and GraphQL APIs must be production-grade from day one
3. **Multi-tenancy architecture:** Organization isolation must be built-in, not bolted on
4. **Scalability by design:** Every component must support horizontal scaling
5. **Security-first mindset:** Encryption, authentication, and authorization are non-negotiable
6. **Incremental delivery:** Ship value every quarter, not in a big-bang release

### 12.2 Next Steps

1. **Week 1-2:** Stakeholder alignment on architecture and roadmap
2. **Week 3-4:** Proof of concept for PostgreSQL migration and REST API v2
3. **Month 2:** Phase 1 kickoff with database schema finalization
4. **Month 3:** First alpha release with API authentication and endpoint management
5. **Month 6:** First beta release with web dashboard and policy management
6. **Month 12:** First GA release with core enterprise features
7. **Month 18:** Compliance features and integrations
8. **Month 24:** Cloud marketplace listings and SaaS platform

### 12.3 Investment Requirements

**Engineering Team:**
- 2 Backend Engineers (Go, PostgreSQL, gRPC)
- 1 Frontend Engineer (React, Next.js)
- 1 DevOps Engineer (Kubernetes, Terraform, CI/CD)
- 1 Security Engineer (authentication, compliance, pentesting)
- 1 QA Engineer (test automation, load testing)

**Infrastructure (Annual):**
- Development: $2,000/month (AWS/GCP)
- Staging: $5,000/month
- Production (multi-region): $15,000/month
- Monitoring/observability: $2,000/month
- Total: ~$300,000/year

**Timeline:** 18-24 months to full enterprise readiness

---

This comprehensive plan provides a blueprint for transforming AfterSec into an enterprise security platform. The phased approach allows for iterative delivery while maintaining focus on the critical path. By following this roadmap, AfterSec can compete effectively in the enterprise macOS security market.

**Recommended Immediate Action:** Begin Phase 1 with database schema design and proof-of-concept migration from file storage to PostgreSQL. This foundational work will validate the architecture and de-risk the transformation.
