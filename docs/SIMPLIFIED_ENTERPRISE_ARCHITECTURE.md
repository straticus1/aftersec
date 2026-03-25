# SIMPLIFIED ENTERPRISE ARCHITECTURE
## AfterSec: Dual-Mode Client + Optional Management Server

**Date:** 2026-03-24
**Version:** 2.0 (Simplified)
**Architecture Philosophy:** Client-first with optional centralized management

---

## EXECUTIVE SUMMARY

AfterSec will operate in **two modes** with a single client binary:

1. **Standalone Mode** (default): Works exactly like now - local storage, no network dependencies
2. **Enterprise Mode** (opt-in): Connects to management server via authenticated gRPC for centralized orchestration

**Key Insight:** All core security features, scanning, forensics, and Starlark plugins remain **client-side**. The management server is purely for orchestration, aggregation, and visualization.

**Timeline:** 12-16 months for full enterprise readiness (vs 24 months in complex version)

---

## 1. ARCHITECTURE OVERVIEW

### 1.1 High-Level Design

```
┌───────────────────────────────────────────────────────────────────────┐
│  AfterSec Client (aftersecd) - Runs on every endpoint                │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  Core Engine (works in both modes):                          │    │
│  │  ────────────────────────────────────────────────────────    │    │
│  │  • Security scanning (SIP, Firewall, Gatekeeper, etc.)       │    │
│  │  • Forensics & memory analysis (YARA-like signatures)        │    │
│  │  • Syscall monitoring (dtrace/eBPF)                          │    │
│  │  • Starlark plugin execution (client-side)                   │    │
│  │  • Local remediation engine                                  │    │
│  │  • Baseline/drift detection                                  │    │
│  └──────────────────────────────────────────────────────────────┘    │
│                                                                        │
│  ┌────────────────────────┐     ┌─────────────────────────────────┐  │
│  │  STANDALONE MODE       │     │  ENTERPRISE MODE                │  │
│  │  ──────────────────    │     │  ───────────────────            │  │
│  │                        │     │                                 │  │
│  │  • Local storage       │     │  • gRPC client                  │  │
│  │    (~/.aftersec/)      │     │  • mTLS authentication          │  │
│  │                        │     │  • Policy sync from server      │  │
│  │  • No network calls    │     │  • Upload scan results          │  │
│  │                        │     │  • Heartbeat & health           │  │
│  │  • CLI/GUI access      │     │  • Remote command execution     │  │
│  │                        │     │  • Local cache + sync           │  │
│  │  • Self-contained      │     │                                 │  │
│  └────────────────────────┘     └─────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────────┘
                                              │
                                              │ Authenticated gRPC
                                              │ (mTLS + JWT)
                                              ▼
            ┌──────────────────────────────────────────────────────────┐
            │  AfterSec Management Server (Enterprise Only)            │
            │  ──────────────────────────────────────────────────      │
            │                                                           │
            │  ┌─────────────────────┐  ┌──────────────────────────┐  │
            │  │  gRPC Server        │  │  Web Dashboard (Next.js) │  │
            │  │  ────────────────   │  │  ──────────────────────  │  │
            │  │  • Client auth      │  │  • Organization view     │  │
            │  │  • Policy dist.     │  │  • Endpoint inventory    │  │
            │  │  • Result ingestion │  │  • Findings aggregation  │  │
            │  │  • Commands         │  │  • Compliance reports    │  │
            │  └─────────────────────┘  └──────────────────────────┘  │
            │                                                           │
            │  ┌─────────────────────────────────────────────────────┐ │
            │  │  REST/GraphQL API (for external integrations)       │ │
            │  └─────────────────────────────────────────────────────┘ │
            │                                                           │
            │  ┌─────────────────────────────────────────────────────┐ │
            │  │  Data Layer                                         │ │
            │  │  • PostgreSQL (organizations, endpoints, findings)  │ │
            │  │  • Redis (caching, rate limiting)                   │ │
            │  └─────────────────────────────────────────────────────┘ │
            └───────────────────────────────────────────────────────────┘
```

---

## 2. CLIENT ARCHITECTURE (Enhanced for Both Modes)

### 2.1 Client Operation Modes

**Configuration File:** `~/.aftersec/config.yaml`

```yaml
# Standalone mode (default)
mode: standalone
storage:
  type: local
  path: ~/.aftersec/

# Enterprise mode
# mode: enterprise
# server:
#   address: grpc.aftersec.company.com:443
#   tls:
#     cert: /etc/aftersec/client-cert.pem
#     key: /etc/aftersec/client-key.pem
#     ca: /etc/aftersec/ca-cert.pem
#   enrollment_token: "eyJhbG..."  # Used once during initial enrollment
```

### 2.2 Client Features (Available in Both Modes)

#### Core Scanning
- macOS security posture (SIP, Firewall, Gatekeeper, SSH, FileVault)
- Filesystem permissions
- System defaults analysis
- Network configuration
- Certificate validation

#### Forensics & Threat Detection
- Memory scanning (YARA-like pattern matching)
- Behavioral process analysis
- Syscall monitoring (dtrace)
- Persistence mechanism detection
- Entitlement auditing

#### Policy Engine (Client-Side)
- Policy evaluation runs locally
- Starlark scripts execute in sandboxed environment
- Custom security checks
- Auto-remediation (if enabled)

#### Data Storage Strategy

**Standalone Mode:**
```
~/.aftersec/
├── config.yaml
├── history/
│   ├── 2026-03-24T10-30-00Z.json
│   ├── 2026-03-23T04-00-00Z.json
│   └── ...
├── baselines/
│   └── baseline-20260320.json
└── plugins/
    ├── custom-check.star
    └── ...
```

**Enterprise Mode:**
```
~/.aftersec/
├── config.yaml
├── cache/                    # Local cache for offline operation
│   ├── last-sync.json
│   ├── policies/
│   │   └── org-policy-*.json
│   └── pending-upload/       # Queue for when server is unreachable
│       └── scan-*.json
├── credentials/
│   ├── client-cert.pem
│   └── client-key.pem
└── plugins/                  # Can still have local plugins
    └── custom-check.star
```

### 2.3 Client Components

**File Structure (Client):**

```
cmd/aftersecd/
├── main.go                   # Entry point
└── modes/
    ├── standalone.go         # Standalone mode logic
    └── enterprise.go         # Enterprise mode logic

pkg/client/
├── config.go                 # Configuration management
├── storage/
│   ├── local.go              # Standalone storage
│   └── cache.go              # Enterprise cache layer
├── grpc/
│   ├── client.go             # gRPC client for enterprise mode
│   ├── auth.go               # mTLS + JWT authentication
│   ├── sync.go               # Policy sync, result upload
│   └── heartbeat.go          # Health reporting
└── mode.go                   # Mode detection & switching

pkg/scanners/                 # Same as now, works in both modes
├── macos.go
├── secrets.go
└── vuln.go

pkg/forensics/                # Same as now, client-side execution
├── memory.go
├── behavior.go
├── syscall.go
└── ...

pkg/plugins/                  # Starlark execution (client-side)
└── starlark.go

pkg/core/                     # Core logic (mode-agnostic)
├── state.go
├── diff.go
├── remediate.go
└── ...
```

---

## 3. MANAGEMENT SERVER ARCHITECTURE (Enterprise Only)

### 3.1 Server Components

The management server is **optional** and only needed for enterprise deployments.

**File Structure (Server):**

```
cmd/aftersec-server/
└── main.go                   # Server entry point

pkg/server/
├── grpc/
│   ├── server.go             # gRPC server implementation
│   ├── enrollment.go         # Client enrollment
│   ├── policy.go             # Policy distribution
│   ├── results.go            # Scan result ingestion
│   ├── commands.go           # Remote command execution
│   └── auth/
│       ├── mtls.go           # mTLS validation
│       └── jwt.go            # JWT token management
├── api/
│   ├── rest/
│   │   ├── router.go
│   │   └── handlers/
│   │       ├── organizations.go
│   │       ├── endpoints.go
│   │       ├── policies.go
│   │       ├── findings.go
│   │       └── compliance.go
│   └── graphql/
│       ├── schema.graphql
│       └── resolvers/
├── database/
│   ├── client.go
│   └── migrations/
├── repository/               # Data access layer
│   ├── organizations.go
│   ├── endpoints.go
│   ├── policies.go
│   ├── scans.go
│   └── findings.go
└── services/
    ├── policy_distributor.go
    ├── compliance_reporter.go
    ├── alert_dispatcher.go
    └── licensing.go
```

### 3.2 gRPC Protocol Definition

**`api/proto/aftersec.proto`:**

```protobuf
syntax = "proto3";

package aftersec.v1;

option go_package = "aftersec/pkg/proto/v1";

// ==============================================================================
// Client-to-Server Service
// ==============================================================================

service AfterSecManagement {
  // Enrollment - One-time registration of new client
  rpc EnrollClient(EnrollmentRequest) returns (EnrollmentResponse);

  // Heartbeat - Periodic health check and command polling
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // Policy Sync - Get policies assigned to this endpoint
  rpc GetPolicies(GetPoliciesRequest) returns (GetPoliciesResponse);

  // Result Upload - Send scan results to server
  rpc UploadScanResult(ScanResult) returns (UploadResponse);

  // Stream results for large scans
  rpc StreamScanResults(stream ScanResult) returns (UploadResponse);

  // Syscall Alerts - Real-time threat alerts
  rpc ReportSyscallAlert(SyscallAlert) returns (AlertResponse);
}

// ==============================================================================
// Messages
// ==============================================================================

message EnrollmentRequest {
  string enrollment_token = 1;      // Provided by admin during setup
  string hostname = 2;
  string platform = 3;              // macos, linux, windows
  string platform_version = 4;
  string agent_version = 5;
  string ip_address = 6;
  string mac_address = 7;
  map<string, string> metadata = 8;
}

message EnrollmentResponse {
  string endpoint_id = 1;           // UUID for this endpoint
  string client_certificate = 2;    // mTLS cert (PEM)
  string client_key = 3;            // mTLS key (PEM)
  string jwt_token = 4;             // Long-lived JWT for API access
  int64 heartbeat_interval_seconds = 5;
  ServerConfig server_config = 6;
}

message ServerConfig {
  string grpc_endpoint = 1;
  repeated string api_endpoints = 2;
  map<string, string> settings = 3;
}

message HeartbeatRequest {
  string endpoint_id = 1;
  int64 timestamp = 2;
  EndpointStatus status = 3;
  ResourceMetrics metrics = 4;
  string agent_version = 5;
}

message HeartbeatResponse {
  bool policies_updated = 1;        // Client should call GetPolicies
  bool command_available = 2;       // Client should execute command
  Command pending_command = 3;
  int64 next_heartbeat_seconds = 4;
}

message ResourceMetrics {
  double cpu_percent = 1;
  uint64 memory_bytes = 2;
  uint64 disk_bytes = 3;
  uint32 active_processes = 4;
}

message GetPoliciesRequest {
  string endpoint_id = 1;
  int64 last_sync_timestamp = 2;   // Get only updates since this time
}

message GetPoliciesResponse {
  repeated Policy policies = 1;
  int64 sync_timestamp = 2;
}

message Policy {
  string id = 1;
  string name = 2;
  string description = 3;
  PolicyType type = 4;
  string compliance_framework = 5;  // CIS, NIST, etc.
  repeated Rule rules = 6;
  RemediationMode remediation_mode = 7;
}

message Rule {
  string category = 1;
  string name = 2;
  string expected_value = 3;
  string severity = 4;
  string remediation_script = 5;
  string starlark_check = 6;        // Optional Starlark code for custom check
}

message ScanResult {
  string endpoint_id = 1;
  string scan_id = 2;                // Client-generated UUID
  ScanMetadata metadata = 3;
  repeated Finding findings = 4;
  int64 timestamp = 5;
}

message ScanMetadata {
  string scan_type = 1;              // scheduled, manual, policy_check
  int64 started_at = 2;
  int64 completed_at = 3;
  string triggered_by = 4;           // user, system, policy
}

message Finding {
  string category = 1;
  string name = 2;
  string description = 3;
  string severity = 4;
  string current_value = 5;
  string expected_value = 6;
  bool passed = 7;
  string cis_benchmark = 8;
  string nist_control = 9;
  repeated string compliance_frameworks = 10;
  string remediation_script = 11;
  string log_context = 12;
}

message UploadResponse {
  bool success = 1;
  string message = 2;
  string scan_id = 3;                // Server-assigned ID
}

message SyscallAlert {
  string endpoint_id = 1;
  int64 timestamp = 2;
  int32 pid = 3;
  string command = 4;
  string pattern = 5;                // What triggered the alert
  string severity = 6;
  map<string, string> details = 7;
}

message AlertResponse {
  bool acknowledged = 1;
  string action = 2;                 // kill, monitor, ignore
}

message Command {
  string command_id = 1;
  CommandType type = 2;
  map<string, string> parameters = 3;
}

// ==============================================================================
// Enums
// ==============================================================================

enum EndpointStatus {
  ENDPOINT_STATUS_UNSPECIFIED = 0;
  ENDPOINT_STATUS_HEALTHY = 1;
  ENDPOINT_STATUS_WARNING = 2;
  ENDPOINT_STATUS_CRITICAL = 3;
}

enum PolicyType {
  POLICY_TYPE_UNSPECIFIED = 0;
  POLICY_TYPE_COMPLIANCE = 1;
  POLICY_TYPE_CUSTOM = 2;
  POLICY_TYPE_BASELINE = 3;
}

enum RemediationMode {
  REMEDIATION_MODE_UNSPECIFIED = 0;
  REMEDIATION_MODE_MANUAL = 1;
  REMEDIATION_MODE_AUTOMATIC = 2;
  REMEDIATION_MODE_NOTIFY = 3;
}

enum CommandType {
  COMMAND_TYPE_UNSPECIFIED = 0;
  COMMAND_TYPE_SCAN = 1;
  COMMAND_TYPE_UPDATE_POLICY = 2;
  COMMAND_TYPE_REMEDIATE = 3;
  COMMAND_TYPE_RESTART = 4;
}
```

### 3.3 Database Schema (Server Only)

**Simplified schema focused on management:**

```sql
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

-- Audit Logs
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id),
    user_id UUID REFERENCES users(id),
    endpoint_id UUID REFERENCES endpoints(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    ip_address INET,
    details JSONB DEFAULT '{}',
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_audit_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp DESC);
```

---

## 4. IMPLEMENTATION ROADMAP

### Phase 1: Client Enhancements (Months 1-3)

**Goal:** Make the client work perfectly in both modes

#### Deliverables:

1. **Mode Detection & Configuration**
   - Implement mode switching (`standalone` vs `enterprise`)
   - Configuration file parsing
   - Environment variable overrides

2. **Storage Abstraction**
   - Interface for storage backend
   - Local storage implementation (existing)
   - Cache layer for enterprise mode
   - Offline queue for pending uploads

3. **gRPC Client Implementation**
   - Protocol buffer definitions
   - mTLS authentication
   - Enrollment flow
   - Heartbeat mechanism
   - Policy sync
   - Result upload (streaming for large scans)

4. **Client-Side Features (Mode-Agnostic)**
   - Enhanced Starlark plugin system
   - Better forensics reporting
   - Improved syscall monitoring
   - Multiple scan profiles (quick, standard, thorough)

**Files to Create/Modify:**

```
pkg/client/
├── config.go                 # NEW: Mode configuration
├── mode.go                   # NEW: Mode detection
├── storage/
│   ├── interface.go          # NEW: Storage abstraction
│   ├── local.go              # REFACTOR: Existing file storage
│   └── cache.go              # NEW: Enterprise mode cache
└── grpc/
    ├── client.go             # NEW: gRPC client
    ├── enrollment.go         # NEW: Enrollment flow
    ├── sync.go               # NEW: Policy/result sync
    └── auth.go               # NEW: mTLS + JWT

api/proto/
└── aftersec.proto            # NEW: Protocol definition

cmd/aftersecd/
├── main.go                   # MODIFY: Add mode switching
└── modes/
    ├── standalone.go         # NEW: Standalone mode
    └── enterprise.go         # NEW: Enterprise mode
```

---

### Phase 2: Management Server (Months 4-7)

**Goal:** Build minimal viable management server

#### Deliverables:

1. **gRPC Server**
   - Client enrollment
   - Authentication (mTLS + JWT)
   - Heartbeat handling
   - Policy distribution
   - Result ingestion

2. **Database Layer**
   - PostgreSQL schema
   - Repository pattern
   - Migrations

3. **Basic REST API**
   - Organization management
   - Endpoint inventory
   - Policy CRUD
   - Finding queries

4. **Authentication & Authorization**
   - User management
   - JWT tokens
   - Basic RBAC (admin, viewer)

**Files to Create:**

```
cmd/aftersec-server/
└── main.go                   # NEW: Server entry point

pkg/server/
├── grpc/
│   ├── server.go             # NEW: gRPC server
│   ├── enrollment.go         # NEW: Client enrollment
│   ├── policy.go             # NEW: Policy distribution
│   ├── results.go            # NEW: Result ingestion
│   └── auth/
│       ├── mtls.go           # NEW: mTLS validation
│       └── jwt.go            # NEW: JWT management
├── api/
│   └── rest/
│       ├── router.go         # NEW: REST API router
│       └── handlers/
├── database/
│   ├── client.go             # NEW: DB connection
│   └── migrations/           # NEW: SQL migrations
└── repository/
    ├── organizations.go      # NEW
    ├── endpoints.go          # NEW
    ├── policies.go           # NEW
    └── findings.go           # NEW

migrations/
├── 001_initial_schema.up.sql
└── 001_initial_schema.down.sql
```

---

### Phase 3: Web Dashboard (Months 8-10)

**Goal:** Build beautiful, functional web UI

#### Deliverables:

1. **Next.js Application**
   - Organization dashboard
   - Endpoint inventory (table + filters)
   - Real-time endpoint status
   - Finding explorer
   - Policy management
   - Compliance reports

2. **Real-Time Updates**
   - WebSocket connection
   - Live endpoint status
   - Scan progress

3. **User Experience**
   - Dark mode
   - Responsive design
   - Export capabilities (PDF, CSV)

**Files to Create:**

```
web/
├── src/
│   ├── app/
│   │   ├── (auth)/
│   │   │   └── login/
│   │   └── (dashboard)/
│   │       ├── endpoints/
│   │       ├── findings/
│   │       ├── policies/
│   │       └── compliance/
│   ├── components/
│   │   ├── ui/               # shadcn components
│   │   ├── charts/
│   │   └── tables/
│   └── lib/
│       ├── api.ts            # API client
│       └── auth.ts           # Auth helpers
├── package.json
└── next.config.js
```

---

### Phase 4: Enterprise Features (Months 11-14)

**Goal:** Add enterprise-critical features

#### Deliverables:

1. **SSO Integration**
   - SAML 2.0
   - OAuth2 (Google, Microsoft, Okta)
   - LDAP/Active Directory

2. **Enhanced RBAC**
   - Custom roles
   - Granular permissions
   - Team-based access

3. **Compliance Reporting**
   - CIS Benchmarks
   - NIST 800-53
   - SOC2 evidence
   - PDF/Excel export

4. **Licensing**
   - Seat-based licensing
   - Feature gates
   - Trial management

5. **Webhooks**
   - Event dispatcher
   - Retry logic
   - HMAC signatures

**Files to Create:**

```
pkg/server/
├── auth/
│   └── sso/
│       ├── saml.go
│       ├── oauth2.go
│       └── ldap.go
├── services/
│   ├── compliance_reporter.go
│   ├── webhook_dispatcher.go
│   └── licensing.go
└── rbac/
    ├── permissions.go
    └── casbin_adapter.go
```

---

### Phase 5: Deployment & Packaging (Months 15-16)

**Goal:** Make it easy to deploy everywhere

#### Deliverables:

1. **Containerization**
   - Docker images (client + server)
   - Docker Compose for local dev
   - Multi-arch builds

2. **Kubernetes**
   - Helm chart
   - StatefulSets for server
   - DaemonSets for agents (if k8s deployment)

3. **Package Management**
   - Homebrew formula (macOS client)
   - .deb package (Linux client)
   - .rpm package (Linux client)
   - Windows MSI (future)

4. **Infrastructure as Code**
   - Terraform modules (AWS, GCP, Azure)
   - Ansible playbooks (agent deployment)

5. **CI/CD**
   - GitHub Actions
   - Automated testing
   - Release automation

**Files to Create:**

```
Dockerfile.client
Dockerfile.server
docker-compose.yml

charts/aftersec/
├── Chart.yaml
├── values.yaml
└── templates/

terraform/
├── aws/
├── gcp/
└── azure/

packaging/
├── homebrew/aftersec.rb
├── debian/
└── rpm/

.github/workflows/
├── ci.yml
├── release.yml
└── security-scan.yml
```

---

## 5. CLIENT-SERVER INTERACTION FLOWS

### 5.1 Enrollment Flow

```
Client                                    Server
  │                                         │
  │  1. EnrollClient(token, metadata) ─────>│
  │                                         │
  │                                         │ Validate token
  │                                         │ Create endpoint record
  │                                         │ Generate mTLS cert + JWT
  │                                         │
  │ <───── EnrollmentResponse              │
  │        (endpoint_id, cert, key, JWT)   │
  │                                         │
  │  2. Save credentials locally           │
  │     Switch to enterprise mode          │
  │                                         │
  │  3. Heartbeat() ───────────────────────>│
  │                                         │
  │ <───── HeartbeatResponse               │
  │        (policies_updated=true)         │
  │                                         │
  │  4. GetPolicies() ─────────────────────>│
  │                                         │
  │ <───── GetPoliciesResponse             │
  │        (policies[])                    │
  │                                         │
  │  5. Run scan with policies             │
  │                                         │
  │  6. UploadScanResult(results) ────────>│
  │                                         │
  │ <───── UploadResponse                  │
  │        (success, scan_id)              │
  │                                         │
```

### 5.2 Normal Operation Flow

```
Client                                    Server
  │                                         │
  │  Every 60s: Heartbeat() ──────────────>│
  │                                         │
  │ <───── HeartbeatResponse               │
  │        (command_available=false)       │
  │                                         │
  │  Every 6 hours: Run scheduled scan     │
  │                                         │
  │  UploadScanResult(results) ───────────>│
  │                                         │
  │ <───── UploadResponse                  │
  │                                         │
  │  Syscall alert detected!               │
  │                                         │
  │  ReportSyscallAlert(alert) ───────────>│
  │                                         │
  │ <───── AlertResponse                   │
  │        (action=monitor)                │
  │                                         │
```

### 5.3 Remote Command Flow

```
Admin (Web UI)                Client                Server
      │                         │                     │
      │  1. Click "Run Scan"    │                     │
      │  ──────────────────────────────────────────> │
      │                         │                     │
      │                         │                     │ Queue command
      │                         │                     │
      │                         │  2. Heartbeat() ───>│
      │                         │                     │
      │                         │ <─── HeartbeatResp │
      │                         │     (command_avail) │
      │                         │                     │
      │                         │  3. Execute scan    │
      │                         │                     │
      │                         │  4. Upload results ─>│
      │                         │                     │
      │ <────────────────────────────────────────────│
      │  5. Show results in UI  │                     │
      │                         │                     │
```

---

## 6. DEPLOYMENT SCENARIOS

### 6.1 Standalone Deployment (Individual/Small Team)

**Use Case:** Developer securing their own Mac, small team without centralized IT

**Setup:**
```bash
# Install client
brew install aftersec

# Configure (defaults to standalone mode)
aftersec init

# Run scan
aftersec scan

# View results
aftersec-gui
```

**No server needed!** Everything works locally.

---

### 6.2 Enterprise Deployment (Small - Single Server)

**Use Case:** 50-500 endpoints, single organization

**Architecture:**
```
┌─────────────────────────────────────┐
│  Management Server (Single VM)      │
│  • aftersec-server                  │
│  • PostgreSQL                       │
│  • Redis                            │
│  • nginx (reverse proxy)            │
└─────────────────────────────────────┘
         ▲         ▲         ▲
         │         │         │
    ┌────┘    ┌────┘    └────┐
    │         │              │
┌───┴───┐ ┌───┴───┐     ┌───┴───┐
│ Mac 1 │ │ Mac 2 │ ... │ Mac N │
│ Agent │ │ Agent │     │ Agent │
└───────┘ └───────┘     └───────┘
```

**Server Setup:**
```bash
# Deploy with Docker Compose
docker-compose up -d

# Create first organization
aftersec-server org create --name "Acme Corp"

# Generate enrollment tokens
aftersec-server enrollment create --org acme-corp --count 100
```

**Client Setup:**
```bash
# Install agent
brew install aftersec

# Enroll with server
sudo aftersec enroll \
  --server grpc.aftersec.acme.com:443 \
  --token eyJhbGciOi...

# Agent now runs in enterprise mode
sudo systemctl start aftersecd
```

---

### 6.3 Enterprise Deployment (Large - Kubernetes)

**Use Case:** 1000+ endpoints, multi-region, high availability

**Architecture:**
```
                    ┌──────────────────────┐
                    │  Global Load Balancer │
                    │  (Route 53, CloudFlare)│
                    └──────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
    ┌─────────▼────────┐         ┌─────────▼────────┐
    │  Region: US-East │         │  Region: EU-West │
    │                  │         │                  │
    │  Kubernetes      │         │  Kubernetes      │
    │  ┌────────────┐  │         │  ┌────────────┐  │
    │  │ aftersec-  │  │         │  │ aftersec-  │  │
    │  │ server     │  │         │  │ server     │  │
    │  │ (3 pods)   │  │         │  │ (3 pods)   │  │
    │  └────────────┘  │         │  └────────────┘  │
    │                  │         │                  │
    │  PostgreSQL RDS  │         │  PostgreSQL RDS  │
    │  (Multi-AZ)      │         │  (Read replica)  │
    │                  │         │                  │
    │  Redis Cluster   │         │  Redis Cluster   │
    └──────────────────┘         └──────────────────┘
         ▲                             ▲
         │                             │
    5K endpoints                  5K endpoints
    (Americas)                    (Europe)
```

**Deployment:**
```bash
# Deploy with Helm
helm install aftersec ./charts/aftersec \
  --set postgresql.enabled=false \
  --set postgresql.host=rds.us-east-1.amazonaws.com \
  --set redis.enabled=false \
  --set redis.host=redis.us-east-1.amazonaws.com \
  --set replicas=3 \
  --set ingress.enabled=true \
  --set ingress.host=api.aftersec.company.com

# Scale based on load
kubectl autoscale deployment aftersec-server \
  --min=3 --max=20 --cpu-percent=70
```

---

## 7. FEATURE COMPARISON: STANDALONE vs ENTERPRISE

| Feature | Standalone Mode | Enterprise Mode |
|---------|----------------|-----------------|
| **Security Scanning** | ✅ Full | ✅ Full |
| **Forensics & Memory Analysis** | ✅ Full | ✅ Full |
| **Syscall Monitoring** | ✅ Full | ✅ Full (+ server alerts) |
| **Starlark Plugins** | ✅ Client-side | ✅ Client-side |
| **Remediation** | ✅ Manual | ✅ Manual + Server-triggered |
| **Storage** | Local files | Server + local cache |
| **Baseline/Drift Detection** | ✅ Local | ✅ Centralized |
| **GUI** | ✅ Local GUI | ✅ Local GUI + Web Dashboard |
| **CLI** | ✅ Full | ✅ Full |
| **Policy Management** | Local config | ✅ Server-distributed |
| **Multi-endpoint View** | ❌ | ✅ Web dashboard |
| **Compliance Reporting** | Single device | ✅ Organization-wide |
| **User Management** | ❌ | ✅ Multi-user with RBAC |
| **SSO Integration** | ❌ | ✅ SAML, OAuth2, LDAP |
| **Webhooks** | ❌ | ✅ Event notifications |
| **Licensing** | Free/Basic | ✅ Seat-based |
| **Support** | Community | ✅ Enterprise support |

---

## 8. TECHNOLOGY STACK (Simplified)

### 8.1 Client (Both Modes)

- **Language:** Go 1.22+
- **UI:** Fyne (existing GUI)
- **Plugins:** Starlark
- **Storage:** Local files (standalone) + local cache (enterprise)
- **gRPC:** grpc-go with mTLS

### 8.2 Server (Enterprise Only)

**Backend:**
- **Language:** Go 1.22+
- **gRPC Server:** grpc-go
- **REST API:** Gin framework
- **GraphQL:** gqlgen (optional, Phase 4)
- **Database:** PostgreSQL 15+
- **Caching:** Redis 7+
- **Auth:** JWT + mTLS

**Frontend:**
- **Framework:** Next.js 14+
- **UI:** Tailwind CSS + shadcn/ui
- **Charts:** Recharts
- **Real-time:** WebSocket

**Infrastructure:**
- **Containers:** Docker
- **Orchestration:** Kubernetes + Helm
- **Reverse Proxy:** nginx or Traefik
- **TLS:** Let's Encrypt (cert-manager)

---

## 9. LICENSING MODEL

### 9.1 Tiers

**Free (Standalone)**
- Single endpoint
- All scanning features
- Local storage
- Community support
- No server required

**Professional (Enterprise)**
- Up to 100 endpoints
- Management server
- Web dashboard
- Email support
- $29/endpoint/year

**Enterprise (Enterprise)**
- Unlimited endpoints
- SSO integration
- Advanced RBAC
- Compliance reporting
- Priority support
- Custom SLA
- $99/endpoint/year (volume discounts)

---

## 10. MIGRATION PATH

### 10.1 For Existing Standalone Users

**Zero Disruption:**
- Upgrade client to new version
- Still works in standalone mode by default
- Optionally enroll in enterprise mode when ready

**Migration Script:**
```bash
# 1. Upgrade client
brew upgrade aftersec

# 2. (Optional) Enroll in enterprise
sudo aftersec enroll --server grpc.company.com:443 --token TOKEN

# 3. Historical data can be uploaded to server
aftersec migrate-history --upload
```

### 10.2 For New Enterprise Deployments

**Clean Start:**
1. Deploy management server (Docker Compose or Kubernetes)
2. Create organization and enrollment tokens
3. Deploy clients with enrollment token
4. Clients auto-enroll and start reporting

---

## 11. SECURITY CONSIDERATIONS

### 11.1 Client-Side Security

**Standalone Mode:**
- File permissions: 0600 for sensitive data
- No network exposure
- Starlark sandbox for plugins

**Enterprise Mode:**
- mTLS for all gRPC communication
- Certificate rotation
- JWT tokens with expiry
- Local cache encryption (AES-256)
- Secure credential storage

### 11.2 Server-Side Security

- mTLS required for all client connections
- JWT validation with short expiry
- PostgreSQL connection encryption
- Redis password auth
- Row-level security for multi-tenancy
- Audit logging (immutable)
- Rate limiting
- DDoS protection (via load balancer)

### 11.3 Data Privacy

- Clients never send raw system data (only scan results)
- Sensitive values can be masked
- Data retention policies
- GDPR compliance (data deletion)
- Encryption at rest and in transit

---

## 12. PERFORMANCE TARGETS

### 12.1 Client Performance

- Scan completion: < 5 minutes (standard scan)
- Memory usage: < 100MB idle, < 500MB during scan
- CPU usage: < 5% idle, < 25% during scan
- Heartbeat overhead: < 1MB/day network traffic
- Offline operation: Unlimited (queues uploads)

### 12.2 Server Performance

- API latency: p95 < 200ms, p99 < 500ms
- Concurrent clients: 10,000+ per server instance
- Database queries: p95 < 50ms
- Scan ingestion: 1000 scans/minute per instance
- Web dashboard: First paint < 2s

### 12.3 Scalability

- Horizontal scaling: Stateless server design
- Database: Read replicas for scaling reads
- Caching: Redis for hot data
- Message queue: Optional for async processing

---

## 13. OBSERVABILITY

### 13.1 Client Metrics

- Scan duration
- Findings count by severity
- Memory/CPU usage
- gRPC connection health
- Policy sync success rate

### 13.2 Server Metrics (Prometheus)

- Active clients (gauge)
- Scans ingested (counter)
- API request rate (counter)
- API latency (histogram)
- Database connection pool
- Cache hit rate

### 13.3 Logging

**Client:**
- Structured logging (JSON)
- Log levels: DEBUG, INFO, WARN, ERROR
- Output: stdout + file

**Server:**
- Structured logging (JSON)
- Centralized: Loki or ELK
- Request tracing
- Audit logs (separate table)

---

## 14. TESTING STRATEGY

### 14.1 Client Testing

**Unit Tests:**
- Scanner logic
- Policy evaluation
- Starlark execution
- Storage abstraction

**Integration Tests:**
- gRPC client communication
- Enrollment flow
- Offline queue

**Platform Tests:**
- macOS 13, 14, 15
- Intel + Apple Silicon

### 14.2 Server Testing

**Unit Tests:**
- gRPC handlers
- REST API handlers
- Database repositories

**Integration Tests:**
- Full enrollment flow
- Policy distribution
- Multi-client scenarios

**Load Tests:**
- 10,000 concurrent clients
- 1000 scans/minute ingestion
- API stress testing (k6)

---

## 15. DOCUMENTATION PLAN

### 15.1 User Documentation

```
docs/
├── quickstart/
│   ├── standalone-mode.md
│   └── enterprise-mode.md
├── user-guide/
│   ├── scanning.md
│   ├── plugins.md
│   └── remediation.md
├── admin-guide/
│   ├── server-installation.md
│   ├── client-deployment.md
│   ├── enrollment.md
│   └── monitoring.md
└── api/
    ├── grpc-protocol.md
    └── rest-api.md
```

### 15.2 Developer Documentation

```
docs/dev/
├── architecture.md
├── client-design.md
├── server-design.md
├── contributing.md
└── plugin-development.md
```

---

## 16. SUCCESS METRICS

### 16.1 Adoption Metrics

- **Standalone users:** 10,000+ in Year 1
- **Enterprise customers:** 50+ in Year 1
- **Managed endpoints:** 10,000+ in Year 1

### 16.2 Technical Metrics

- **Client uptime:** 99.9%
- **Server uptime:** 99.95%
- **Scan success rate:** > 99%
- **Client-server sync success:** > 99.5%

### 16.3 Quality Metrics

- **Test coverage:** > 80%
- **Critical bugs:** < 5 per release
- **Security vulnerabilities:** 0 critical/high

---

## 17. TIMELINE SUMMARY

| Phase | Duration | Deliverables | Effort |
|-------|----------|--------------|--------|
| **Phase 1: Client** | Months 1-3 | Dual-mode client, gRPC client | 1-2 engineers |
| **Phase 2: Server** | Months 4-7 | Management server, DB, API | 2-3 engineers |
| **Phase 3: Web UI** | Months 8-10 | Next.js dashboard | 1 frontend engineer |
| **Phase 4: Enterprise** | Months 11-14 | SSO, RBAC, compliance, webhooks | 2-3 engineers |
| **Phase 5: Deployment** | Months 15-16 | Containers, K8s, packages | 1 DevOps engineer |

**Total Timeline:** 16 months
**Team Size:** 3-4 engineers

---

## 18. CONCLUSION

This simplified architecture provides:

1. **Immediate Value:** Standalone mode works perfectly for individuals
2. **Easy Adoption:** No server required to get started
3. **Clear Upgrade Path:** Enroll in enterprise when ready
4. **Clean Separation:** Client features vs server features
5. **Scalability:** Server can handle 10,000+ endpoints
6. **Simplicity:** Less complexity, faster time to market

**Next Steps:**

1. **Week 1:** Review and approve architecture
2. **Week 2:** Set up development environment
3. **Week 3:** Start Phase 1 (client mode switching)
4. **Month 1:** Complete gRPC protocol definition
5. **Month 2:** First working prototype (client + server enrollment)

**Key Decisions Needed:**

1. Licensing model pricing
2. Free tier limits
3. Target cloud platform (AWS, GCP, Azure, multi-cloud?)
4. Open source vs proprietary
5. Branding and marketing strategy

This architecture is **production-ready, scalable, and maintainable** while keeping the best parts of AfterSec (macOS security expertise, Starlark plugins, forensics) at the core.
