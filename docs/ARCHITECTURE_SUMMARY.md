# AfterSec Architecture Summary

## Core Principle: Client-First with Optional Server

AfterSec is built on a **client-first architecture** where all core security functionality lives in the client. The management server is **completely optional** and only provides centralized orchestration for enterprise deployments.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      STANDALONE MODE                             │
│                     (No Server Required)                         │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  AfterSec Client                                           │ │
│  │  ━━━━━━━━━━━━━━━━                                         │ │
│  │  • All security scanning                                   │ │
│  │  • Forensics & memory analysis                            │ │
│  │  • Syscall monitoring                                      │ │
│  │  • Starlark plugins                                        │ │
│  │  • Local remediation                                       │ │
│  │  • Baseline/drift detection                               │ │
│  │  • CLI + GUI + Daemon                                      │ │
│  │  • Local storage (~/.aftersec/)                           │ │
│  │                                                             │ │
│  │  Works perfectly for:                                      │ │
│  │  ✓ Individual users                                        │ │
│  │  ✓ Developers                                              │ │
│  │  ✓ Small teams                                             │ │
│  │  ✓ Air-gapped environments                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘

                              OR

┌─────────────────────────────────────────────────────────────────┐
│                      ENTERPRISE MODE                             │
│                 (Optional Management Server)                     │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  AfterSec Clients (10, 100, 10000+ endpoints)             │ │
│  │  ━━━━━━━━━━━━━━━━                                         │ │
│  │  • Same features as standalone mode                        │ │
│  │  • PLUS: Connect to management server via gRPC            │ │
│  │  • Local cache for offline operation                       │ │
│  │  • Sync policies from server                              │ │
│  │  • Upload scan results                                     │ │
│  │  • Receive remote commands                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│                            ▲                                     │
│                            │ Authenticated gRPC (mTLS + JWT)    │
│                            ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  AfterSec Management Server                               │ │
│  │  ━━━━━━━━━━━━━━━━━━━━━━━                                 │ │
│  │  • Organization/user management                            │ │
│  │  • Policy distribution                                     │ │
│  │  • Result aggregation                                      │ │
│  │  • Compliance reporting                                    │ │
│  │  • Web dashboard                                           │ │
│  │  • REST/GraphQL APIs                                       │ │
│  │  • Database (PostgreSQL)                                   │ │
│  │  • Caching (Redis)                                         │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  Benefits of Enterprise Mode:                                    │
│  ✓ Centralized visibility across all endpoints                  │
│  ✓ Organization-wide compliance reports                          │
│  ✓ Policy distribution at scale                                 │
│  ✓ Multi-user access with RBAC                                  │
│  ✓ SSO integration                                               │
│  ✓ Webhooks and integrations                                     │
└─────────────────────────────────────────────────────────────────┘
```

---

## AI & Threat Intelligence Layer

### Multi-LLM AI Analysis (SWARM Mode)

AfterSec integrates multiple LLM providers for consensus-based threat analysis:

```
┌──────────────────────────────────────────────────────────────┐
│                   THREAT DETECTED                             │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Parallel Analysis by Multiple LLMs                    │  │
│  │                                                         │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │  │  ChatGPT    │  │   Claude    │  │   Gemini    │   │  │
│  │  │  (OpenAI)   │  │ (Anthropic) │  │  (Google)   │   │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  │        ↓                ↓                  ↓           │  │
│  │    Analysis 1      Analysis 2        Analysis 3       │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Judge LLM synthesizes consensus verdict              │  │
│  │  • Threat assessment                                   │  │
│  │  • Confidence score                                    │  │
│  │  • Attribution (APT group)                             │  │
│  │  • Remediation command                                 │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**Features:**
- **Graceful degradation**: Works with 1, 2, or 3 LLMs available
- **Error handling**: Logs failures, continues with available models
- **Attribution**: Identifies known threat actors (APT28, Lazarus, etc.)
- **Auto-remediation**: Generates macOS-specific bash commands

**Implementation:** `pkg/ai/analyst.go`
- `AnalyzeThreatSwarm()`: Multi-model consensus
- `AnalyzeThreat()`: Single model analysis
- `AnalyzeBinarySemantics()`: NLP-based malware detection

### Dark Web Threat Intelligence

Integrated DarkAPI.io for proactive threat detection:

```
┌──────────────────────────────────────────────────────────────┐
│           DARK WEB INTELLIGENCE PIPELINE                      │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  DarkAPI.io Client (pkg/threatintel/darkapi.go)       │  │
│  │  • Retry logic with exponential backoff                │  │
│  │  • Rate limiting (60 req/min)                          │  │
│  │  • 15-minute intelligent caching                       │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Data Sources                                           │  │
│  │  • 15B+ breached credentials                           │  │
│  │  • Malware hashes (MD5/SHA1/SHA256)                   │  │
│  │  • C2 server IPs/domains                              │  │
│  │  • Dark web forums & marketplaces                      │  │
│  │  • Paste sites & Telegram                              │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Correlation Engine (pkg/threatintel/correlator.go)   │  │
│  │  • Real-time telemetry correlation                     │  │
│  │  • Process hash → Known malware match                  │  │
│  │  • Network IP → C2 server match                        │  │
│  │  • User credentials → Breach detection                 │  │
│  │  • Confidence scoring                                   │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Enhanced AI Analysis                                   │  │
│  │  LLM receives dark web context for:                    │  │
│  │  • Higher confidence scores (60% → 98%)                │  │
│  │  • Threat actor attribution                            │  │
│  │  • IOC-based validation                                │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**Competitive Advantage:**
- CrowdStrike/SentinelOne: Charge $50-100/endpoint/year EXTRA
- AfterSec: Included FREE in Enterprise tier

**Implementation:**
- `pkg/threatintel/darkapi.go`: API client with retry/rate limiting
- `pkg/threatintel/correlator.go`: Real-time correlation engine
- `pkg/threatintel/credential_monitor.go`: Background monitoring service

### Endpoint AI (On-Device Behavioral Learning)

Local machine learning for zero-day detection:

```
┌──────────────────────────────────────────────────────────────┐
│          ENDPOINT AI BEHAVIORAL LEARNING                      │
│                                                                │
│  Phase 1: OBSERVING (Learning Normal Behavior)                │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  • Record process executions                           │  │
│  │  • Track network connections                           │  │
│  │  • Build behavioral baseline                           │  │
│  │  • Vectorize relationships                             │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  Phase 2: TRAINING (Apple Neural Engine)                      │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  • Compress observations into ML model                 │  │
│  │  • Gradient descent / CoreML optimization              │  │
│  │  • Serialize weights to disk                           │  │
│  │  • Auto-promote to Enforcing mode                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  Phase 3: ENFORCING (Real-Time Detection)                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  • Assess anomaly score (0.0-1.0)                      │  │
│  │  • Reconstruction error → Perplexity                   │  │
│  │  • Block high-confidence anomalies (>0.85)            │  │
│  │  • Privacy-preserving (all local, no cloud)           │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**Features:**
- **Privacy-first**: All training happens locally on Apple Neural Engine
- **Zero-day detection**: Catches never-before-seen threats
- **No cloud dependency**: Works in air-gapped environments
- **Adaptive**: Learns your unique environment patterns

**Implementation:** `pkg/ai/endpoint.go`

### Bandit AI (Conversational Security Assistant)

Natural language interface for telemetry queries:

```
┌──────────────────────────────────────────────────────────────┐
│                    BANDIT AI ASSISTANT                        │
│                                                                │
│  User: "Why did the firewall block 10.0.0.5?"                │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Bandit AI (pkg/ai/bandit.go)                          │  │
│  │  • Receives system state snapshot                       │  │
│  │  • XNU kernel logs                                      │  │
│  │  • Network socket data                                  │  │
│  │  • Memory dumps                                         │  │
│  │  • Process telemetry                                    │  │
│  └────────────────────────────────────────────────────────┘  │
│                         ↓                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  LLM Analysis                                           │  │
│  │  "The IP triggered C2 beacon heuristic over DNS.       │  │
│  │   Domain queried: apple-update-metrics.xyz              │  │
│  │   Blocked via Netfilter ASN null-route."               │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**Use Cases:**
- Memory forensics: "Analyze current X-Ray memory baseline"
- Network investigation: "Why was this connection blocked?"
- Compliance queries: "What is our baseline drift status?"
- Detection rule creation: "Write Starlark rule for this behavior"

**Implementation:**
- Backend: `pkg/ai/bandit.go`
- Frontend: `aftersec-dashboard/src/app/bandit/page.tsx`

---

## Key Documents

1. **`CLIENT_ENHANCEMENTS.md`**
   - CLI/GUI/Daemon improvements
   - Works in both standalone and enterprise modes
   - Plugin system, reporting, performance

2. **`SIMPLIFIED_ENTERPRISE_ARCHITECTURE.md`**
   - Dual-mode client architecture
   - gRPC protocol for client/server communication
   - Management server design
   - Database schema
   - Implementation roadmap

3. **`ENTERPRISE_ARCHITECTURE_PLAN.md`**
   - Full enterprise vision (reference)
   - Comprehensive features
   - 24-month roadmap

---

## Deployment Paths

### Path 1: Start Standalone, Add Server Later

```bash
# Month 1: Deploy standalone clients
brew install aftersec
aftersec init
# Users get immediate value

# Month 6: Deploy management server when ready
docker-compose up -d aftersec-server

# Month 6+: Enroll existing clients
aftersec enroll --server grpc.company.com:443 --token TOKEN
# Zero disruption to existing users
```

### Path 2: Enterprise from Day One

```bash
# Deploy server first
helm install aftersec ./charts/aftersec

# Enroll all clients at once
for mac in $(get-mac-list); do
  ssh $mac "aftersec enroll --server grpc.company.com:443 --token $TOKEN"
done
```

---

## Communication Protocol: gRPC

**Why gRPC?**
- Efficient binary protocol (smaller than REST)
- HTTP/2 multiplexing (multiple requests on one connection)
- Built-in streaming (for large scan results)
- Strong typing with Protocol Buffers
- mTLS built-in for security
- Works great for client-server communication

**Protocol Definition:** `api/proto/aftersec.proto`

---

## Next Steps

1. **Phase 1 (Months 1-3): Client Enhancements**
   - Implement dual-mode support in client
   - Enhanced CLI/GUI/Daemon features
   - Everything in `CLIENT_ENHANCEMENTS.md`

2. **Phase 2 (Months 4-7): Management Server**
   - Build optional server component
   - gRPC implementation
   - Database layer
   - Basic web dashboard

3. **Phase 3 (Months 8+): Enterprise Features**
   - SSO integration
   - Advanced compliance
   - Webhooks
   - Advanced RBAC

---

## Technology Stack

### Client (Go)
- CLI: cobra
- GUI: Fyne
- Plugins: Starlark
- gRPC: grpc-go

### Server (Go + Next.js)
- Backend: Go + Gin + gqlgen
- Frontend: Next.js + Tailwind
- Database: PostgreSQL
- Cache: Redis
- Protocol: gRPC + REST + GraphQL

---

**Bottom Line:** Build an amazing standalone client first, add optional server for enterprise scale.
