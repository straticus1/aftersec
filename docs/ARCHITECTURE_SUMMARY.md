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
