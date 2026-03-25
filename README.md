# AfterSec

**Next-Generation macOS Endpoint Detection & Response (EDR) with Multi-LLM AI Threat Analysis**

[![License](https://img.shields.io/badge/license-Proprietary-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8.svg)](https://golang.org)
[![macOS](https://img.shields.io/badge/macOS-10.15+-000000.svg?logo=apple)](https://www.apple.com/macos)

AfterSec is an enterprise-grade endpoint security platform for macOS that combines native Apple Endpoint Security API integration with cutting-edge multi-LLM AI threat analysis. It operates in dual modes: standalone client for individual devices or enterprise mode with centralized management.

---

## 🚀 Key Features

### Enterprise Architecture
- **Dual-Mode Operation**: Standalone client or enterprise-managed deployment
- **gRPC Protocol**: Secure client-server communication with mTLS
- **PostgreSQL Backend**: Multi-tenant database with row-level security
- **REST + GraphQL APIs**: Complete programmatic access
- **Beautiful Dashboard**: Next.js 16 web UI with real-time monitoring
- **Docker Deployment**: Production-ready containerization

### Native macOS EDR
- **Endpoint Security API**: Kernel-level process monitoring (EXEC, CREATE, EXIT events)
- **Unified Log Streaming**: Real-time TCC/authd/security violation detection
- **Code Signature Verification**: Supply chain security with Team ID validation
- **Forensics Analysis**: Memory, persistence, entitlements, and syscall inspection
- **Behavioral Detection**: Advanced threat hunting capabilities

### Multi-LLM AI Analysis (SWARM Mode)
- **OpenAI Integration**: GPT-4o threat analysis
- **Anthropic Claude**: Claude 3.5 Sonnet security reasoning
- **Google Gemini**: Gemini 2.5 Flash rapid triage
- **Consensus Intelligence**: Multi-model threat validation
- **Auto-Remediation**: AI-generated bash remediation scripts
- **Semantic Binary Analysis**: NLP-based malware detection
- **Dynamic Honeypots**: AI-generated deception content

### Security Posture Management
- **Comprehensive Scanning**: SIP, Firewall, Gatekeeper, SSH, TLS, kernel extensions
- **Baseline & Drift Detection**: Track configuration changes over time
- **Compliance Frameworks**: CIS Benchmarks, NIST, SOC2-ready
- **Starlark Plugins**: Custom security checks via Python-like scripting
- **Tuning Engine**: System optimization (sysctl, network, DNS)

---

## 📋 Table of Contents

- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [AI Configuration](#ai-configuration)
- [Enterprise Deployment](#enterprise-deployment)
- [API Reference](#api-reference)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## 🏗️ Architecture

### Standalone Mode (Default)

```
┌─────────────────────────────────────────┐
│         macOS Endpoint                   │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │   AfterSec Client                  │ │
│  │                                    │ │
│  │  • CLI (aftersec)                 │ │
│  │  • GUI (AfterSec Control Panel)  │ │
│  │  • Daemon (aftersecd)             │ │
│  │                                    │ │
│  │  Features:                         │ │
│  │  ✓ Security scanning               │ │
│  │  ✓ EDR monitoring                  │ │
│  │  ✓ AI threat analysis              │ │
│  │  ✓ Local storage                   │ │
│  │  ✓ Starlark plugins                │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Enterprise Mode

```
                      ┌──────────────────────────────────┐
                      │   Management Server (Docker)      │
                      │                                   │
                      │  ┌─────────────────────────────┐ │
                      │  │  gRPC Server (port 9090)    │ │
                      │  │  • mTLS authentication      │ │
                      │  │  • JWT validation           │ │
                      │  │  • Event streaming          │ │
                      │  └─────────────────────────────┘ │
                      │                                   │
                      │  ┌─────────────────────────────┐ │
                      │  │  REST API (port 8080)       │ │
                      │  │  • Organizations CRUD       │ │
                      │  │  • Endpoints management     │ │
                      │  │  • Scan aggregation         │ │
                      │  └─────────────────────────────┘ │
                      │                                   │
                      │  ┌─────────────────────────────┐ │
                      │  │  PostgreSQL 15              │ │
                      │  │  • Multi-tenancy            │ │
                      │  │  • Row-level security       │ │
                      │  └─────────────────────────────┘ │
                      │                                   │
                      │  ┌─────────────────────────────┐ │
                      │  │  Next.js Dashboard          │ │
                      │  │  • NextAuth authentication  │ │
                      │  │  • Real-time monitoring     │ │
                      │  └─────────────────────────────┘ │
                      └──────────────────────────────────┘
                                    ▲
                                    │ gRPC + mTLS
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
     ┌────────▼────────┐   ┌────────▼────────┐   ┌──────▼──────┐
     │  macOS Client 1 │   │  macOS Client 2 │   │  Client N   │
     │                 │   │                 │   │             │
     │  • EDR sensor   │   │  • EDR sensor   │   │  • EDR...   │
     │  • AI analysis  │   │  • AI analysis  │   │  • AI...    │
     │  • Heartbeat    │   │  • Heartbeat    │   │  • ...      │
     └─────────────────┘   └─────────────────┘   └─────────────┘
```

---

## ⚡ Quick Start

### Standalone Client

```bash
# Clone the repository
git clone https://github.com/straticus1/aftersec.git
cd aftersec

# Build all components
./build.sh all

# Run security scan
./bin/aftersec scan

# Launch GUI
./bin/aftersec-gui

# Start EDR daemon (requires root)
sudo ./aftersecd
```

### Enterprise Deployment (Docker)

```bash
# Start full stack (PostgreSQL + Server + Dashboard)
docker-compose up -d

# Generate production certificates
./scripts/generate-certs.sh ./certs 3650

# Enable mTLS for production
export MTLS_ENABLED=true
docker-compose -f docker-compose.prod.yml up -d

# Access dashboard
open http://localhost:3000
```

---

## 📦 Installation

### Prerequisites

- **macOS**: 10.15 (Catalina) or later
- **Go**: 1.22+ (for building from source)
- **Docker**: 20.10+ (for enterprise deployment)
- **Node.js**: 18+ (for dashboard development)
- **Xcode Command Line Tools**: `xcode-select --install`

### Build from Source

```bash
# Install dependencies
go mod download

# Build CLI
./build.sh cli

# Build GUI (native macOS app)
./scripts/build-mac-app.sh

# Build daemon with Endpoint Security
./test_es.sh

# Build server
./build.sh server
```

### Binary Installation

Download pre-built binaries from [Releases](https://github.com/straticus1/aftersec/releases):

```bash
# Extract release
tar -xzf aftersec-v1.0.0-darwin-arm64.tar.gz

# Install to /usr/local/bin
sudo cp bin/* /usr/local/bin/

# Verify installation
aftersec version
```

---

## 🎯 Usage

### Command Line Interface

```bash
# Security Scanning
aftersec scan                          # Full system scan
aftersec scan --strict                 # Strict mode (all checks)
aftersec scan --output json            # JSON output

# Baseline & Drift Detection
aftersec commit                        # Create baseline snapshot
aftersec diff                          # Compare to baseline
aftersec history                       # View commit history

# Enterprise Mode
aftersec enroll --server api.example.com:9090
aftersec heartbeat                     # Send status update
aftersec sync                          # Upload scan results

# Forensics
aftersec forensics memory              # Memory analysis
aftersec forensics persistence         # Persistence mechanisms
aftersec forensics entitlements /path/to/app

# Tuning
aftersec tune sysctl                   # Optimize kernel params
aftersec tune network                  # Network optimization
aftersec tune dns                      # DNS security
```

### Graphical Interface

```bash
# Launch control panel
./bin/aftersec-gui

# Or launch installed app
open "/Applications/AfterSec Control Panel.app"
```

**GUI Features**:
- 📊 Scanner Tab: Real-time security scanning
- 🔍 Diff Tab: Baseline comparison
- 📜 History Tab: Audit log viewer
- ⚙️ Settings Tab: Configuration management
- 🎨 Beautiful cyberpunk-themed UI

### Background Daemon

```bash
# Start daemon (requires root for Endpoint Security)
sudo ./aftersecd

# With configuration
sudo ./aftersecd --config /etc/aftersec/config.yaml

# Run as LaunchDaemon (automatic startup)
sudo cp scripts/com.aftersec.daemon.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.aftersec.daemon.plist
```

**Daemon Capabilities**:
- Real-time process monitoring (Endpoint Security API)
- Unified Log streaming (TCC violations, auth failures)
- AI-powered threat analysis
- Automatic remediation (configurable)
- Resource-aware scheduling

---

## 🤖 AI Configuration

### Supported Providers

AfterSec supports three LLM providers for threat analysis:

| Provider | Model | Speed | Cost | Quality |
|----------|-------|-------|------|---------|
| **Google Gemini** | gemini-2.5-flash | ⚡⚡⚡ | 💰 | ⭐⭐⭐⭐ |
| **Anthropic Claude** | claude-3-5-sonnet | ⚡⚡ | 💰💰💰 | ⭐⭐⭐⭐⭐ |
| **OpenAI** | gpt-4o-mini | ⚡⚡ | 💰💰 | ⭐⭐⭐⭐ |

### Configuration

Edit `~/.aftersec/config.yaml`:

```yaml
daemon:
  ai:
    provider: "gemini"           # openai, anthropic, gemini
    model: "gemini-2.5-flash"    # or gpt-4o-mini, claude-3-5-sonnet-latest
```

### Environment Variables

```bash
# Configure API keys
export GEMINI_API_KEY="your-key-here"
export ANTHROPIC_API_KEY="your-key-here"
export OPENAI_API_KEY="your-key-here"

# Enable SWARM mode (queries all available models)
export AFTERSEC_AI_SWARM=true
```

### AI Features

**1. Threat Analysis**
```bash
# Single-model analysis
aftersec analyze-threat <finding.json>

# Multi-LLM SWARM mode
aftersec analyze-threat --swarm <finding.json>
```

**2. Binary Analysis**
```bash
# Semantic analysis from strings
strings /path/to/binary | aftersec analyze-binary
```

**3. Honeypot Generation**
```bash
# Generate deceptive credentials
aftersec generate-honeypot --type ssh-key
aftersec generate-honeypot --type aws-credentials
```

---

## 🏢 Enterprise Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for comprehensive production deployment guide.

### Quick Enterprise Setup

```bash
# 1. Generate certificates
./scripts/generate-certs.sh ./certs 3650

# 2. Configure environment
cp .env.example .env
vim .env  # Set DATABASE_URL, JWT_SECRET, MTLS_ENABLED

# 3. Deploy stack
docker-compose -f docker-compose.prod.yml up -d

# 4. Configure reverse proxy (Nginx)
# See DEPLOYMENT.md for Nginx configuration

# 5. Enroll clients
aftersec enroll \
  --server api.example.com:9090 \
  --ca-cert certs/ca.crt \
  --client-cert certs/client.crt \
  --client-key certs/client.key
```

### Dashboard Access

- **URL**: http://localhost:3000 (dev) or https://dashboard.example.com (prod)
- **Default Login**: Configure in dashboard settings
- **Features**:
  - Real-time endpoint monitoring
  - Scan history and analysis
  - Threat score visualization
  - Organization management

---

## 📚 API Reference

### REST API Endpoints

```
Health Check
GET /api/v1/health

Organizations
GET    /api/v1/organizations
POST   /api/v1/organizations
GET    /api/v1/organizations/:id
PUT    /api/v1/organizations/:id
DELETE /api/v1/organizations/:id

Endpoints
GET    /api/v1/endpoints?org_id={id}
GET    /api/v1/endpoints/:id
PUT    /api/v1/endpoints/:id
DELETE /api/v1/endpoints/:id

Scans
GET    /api/v1/scans?endpoint_id={id}&org_id={id}&limit={n}
POST   /api/v1/scans
GET    /api/v1/scans/:id
```

### gRPC Protocol

```protobuf
service EnterpriseService {
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  rpc StreamEvents(stream ClientEvent) returns (StreamAck);
  rpc ConnectCommandStream(stream CommandResult) returns (stream ServerCommand);
}
```

See [api/proto/aftersec.proto](api/proto/aftersec.proto) for full protocol definition.

### Authentication

All API requests require JWT authentication:

```bash
# Login to get token
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'

# Use token in requests
curl http://localhost:8080/api/v1/endpoints \
  -H "Authorization: Bearer <token>"
```

---

## 🛠️ Development

### Project Structure

```
aftersec/
├── cmd/
│   ├── aftersec/          # CLI application
│   ├── aftersec-gui/      # Fyne GUI application
│   ├── aftersecd/         # Background daemon
│   └── aftersec-server/   # Management server
├── pkg/
│   ├── ai/                # Multi-LLM threat analyst
│   ├── api/               # gRPC protocol definitions
│   ├── client/            # Client-side logic
│   ├── core/              # Core scanning engine
│   ├── edr/               # Endpoint Security integration
│   ├── forensics/         # Forensics modules
│   ├── plugins/           # Starlark plugin system
│   ├── server/            # Server-side components
│   ├── tuning/            # System optimization
│   └── ui/                # GUI components
├── aftersec-dashboard/    # Next.js web dashboard
├── migrations/            # Database migrations
├── scripts/               # Build and deployment scripts
├── docs/                  # Architecture documentation
└── tests/                 # Integration tests
```

### Building Components

```bash
# CLI only
./build.sh cli

# GUI only
./build.sh gui

# Server only
./build.sh server

# Daemon with Endpoint Security
./test_es.sh

# macOS app bundle
./scripts/build-mac-app.sh

# Everything
./build.sh all
```

### Running Tests

```bash
# Unit tests
go test ./...

# Integration tests
go test ./tests/integration/...

# With coverage
go test -cover ./...
```

### Development Mode

```bash
# Start server (hot reload)
air -c .air.toml

# Start dashboard (hot reload)
cd aftersec-dashboard
npm run dev

# Start database
docker-compose up db
```

---

## 🔒 Security

### Endpoint Security Requirements

The EDR daemon requires the Endpoint Security entitlement:

```xml
<key>com.apple.developer.endpoint-security.client</key>
<true/>
```

**For Development**:
- Ad-hoc signing: `codesign -s - -f ./aftersecd`
- ES initialization will fail gracefully
- Other features continue to work

**For Production**:
- Apple Developer account required
- Provisioning profile with ES capability
- Notarization for distribution

### Hardening Checklist

- [ ] Enable mTLS for gRPC (`MTLS_ENABLED=true`)
- [ ] Use strong JWT secret (`openssl rand -base64 32`)
- [ ] Configure firewall (UFW or macOS firewall)
- [ ] Enable database encryption (SSL mode)
- [ ] Implement rate limiting (Nginx)
- [ ] Regular security updates
- [ ] Audit logging enabled
- [ ] Principle of least privilege

---

## 📊 Comparison to Commercial EDR

| Feature | AfterSec | CrowdStrike | Carbon Black | SentinelOne |
|---------|----------|-------------|--------------|-------------|
| **Endpoint Security API** | ✅ Native | ✅ | ✅ | ✅ |
| **Real-time Monitoring** | ✅ | ✅ | ✅ | ✅ |
| **AI Threat Analysis** | ✅ Multi-LLM SWARM | ⚠️ Single | ⚠️ Single | ⚠️ Single |
| **Auto-Remediation** | ✅ AI-generated | ✅ | ✅ | ✅ |
| **Code Signing** | ✅ | ✅ | ✅ | ✅ |
| **Honeypot Generation** | ✅ AI-powered | ❌ | ❌ | ❌ |
| **Binary Semantics** | ✅ NLP-based | ⚠️ Limited | ⚠️ Limited | ⚠️ Limited |
| **Starlark Plugins** | ✅ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ | ❌ |
| **Cost per Endpoint** | **FREE** | $$$$ | $$$$ | $$$$ |

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Code Style

- Follow standard Go conventions (`gofmt`, `golint`)
- Write tests for new features
- Update documentation
- Add examples for public APIs

---

## 📝 License

Copyright © 2024 AfterSec

This is proprietary software. See [LICENSE](LICENSE) for details.

For commercial licensing inquiries: licensing@aftersec.io

---

## 🙏 Acknowledgments

- **Apple**: Endpoint Security framework
- **Firebase Genkit**: Multi-LLM orchestration
- **Fyne**: Cross-platform GUI toolkit
- **Next.js**: Dashboard framework
- **PostgreSQL**: Database engine

---

## 📞 Support

- **Documentation**: https://docs.aftersec.io
- **Issues**: https://github.com/straticus1/aftersec/issues
- **Discussions**: https://github.com/straticus1/aftersec/discussions
- **Email**: support@aftersec.io

---

## 🗺️ Roadmap

### v1.1 (Q2 2024)
- [ ] Real-time WebSocket dashboard updates
- [ ] API documentation (OpenAPI/Swagger)
- [ ] E2E testing with Playwright
- [ ] Advanced RBAC with Casbin

### v1.2 (Q3 2024)
- [ ] SSO integration (SAML, OAuth2, LDAP)
- [ ] Compliance reporting (CIS, NIST, SOC2)
- [ ] Kubernetes Helm charts
- [ ] Windows Defender integration

### v2.0 (Q4 2024)
- [ ] GraphQL API layer
- [ ] Multi-region deployment
- [ ] Machine learning threat models
- [ ] Mobile app (iOS)

---

<div align="center">

**Built with ❤️ for macOS security professionals**

[Website](https://aftersec.io) • [Documentation](https://docs.aftersec.io) • [Blog](https://blog.aftersec.io)

</div>
