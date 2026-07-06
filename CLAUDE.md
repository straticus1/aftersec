# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AfterSec — a macOS and Linux EDR (Endpoint Detection & Response) platform, licensed under Elastic 2.0. It combines native Apple Endpoint Security API integration with multi-LLM AI threat analysis (OpenAI, Anthropic, Gemini — "SWARM mode"), security posture scanning (SIP, Firewall, Gatekeeper, SSH, TLS, kernel extensions), baseline/drift detection, forensics, and Starlark plugins. It runs in two modes: standalone client on a single device, or enterprise mode with a centralized management server (gRPC + mTLS, REST/GraphQL APIs, PostgreSQL multi-tenant backend, Next.js dashboard).

## Commands

All Go builds go through `./build.sh` (there is no Makefile):

```bash
./build.sh cli        # bin/aftersec (CLI)
./build.sh gui        # bin/aftersec-gui (Fyne GUI)
./build.sh daemon     # bin/aftersecd
./build.sh server     # bin/aftersec-server
./build.sh lib        # bin/afterseclib.so (c-shared, from ./afterseclib)
./build.sh dashboard  # npm install && npm run build in aftersec-dashboard/
./build.sh proto      # regen gRPC code from api/proto/aftersec.proto
./build.sh debug      # all binaries with -N -l (debugger-friendly)
./build.sh all        # everything
./test_es.sh          # build/run daemon with Endpoint Security entitlement
./scripts/build-mac-app.sh   # macOS .app bundle

# Tests
go test ./...                        # unit tests
go test ./tests/integration/...     # integration tests
go test -cover ./...                # coverage
go test ./pkg/patchmgr/             # single package

# Dashboard (aftersec-dashboard/, Next.js 16)
npm run dev / npm run build / npm run lint

# Enterprise stack
docker-compose up db     # just PostgreSQL
docker-compose up        # full stack (see docker-compose.production.yml too)
```

CGO builds pin `MACOSX_DEPLOYMENT_TARGET=11.0` (set by build.sh).

## Architecture

- **Four Go binaries, one module** (`cmd/`): `aftersec` (CLI), `aftersec-gui` (Fyne desktop app), `aftersecd` (background EDR daemon — requires the `com.apple.developer.endpoint-security.client` entitlement on macOS, see `entitlements.plist`), and `aftersec-server` (enterprise management server). All share `pkg/`.
- **Client side** (`pkg/client`, `pkg/core`, `pkg/edr`, `pkg/scanners`, `pkg/forensics`, `pkg/tuning`, `pkg/patchmgr`): `core` is the scanning engine; `edr` wraps the Apple Endpoint Security API (with a Linux variant — see `pkg/edr/es_client_linux*`); `scanners` implement posture checks; `plugins` runs Starlark custom checks.
- **AI layer** (`pkg/ai`): multi-LLM threat analyst — sends events to OpenAI/Anthropic/Gemini, builds consensus verdicts, generates remediation scripts.
- **Server side** (`pkg/server`, `pkg/api`, `api/proto/`, `migrations/`): gRPC server (port 9090, mTLS + JWT) for client enrollment and event streaming; REST API (port 8080) for orgs/endpoints/scans; PostgreSQL 15 with row-level security for multi-tenancy. Protocol is defined in `api/proto/aftersec.proto` — regenerate with `./build.sh proto` after editing.
- **Data flow (enterprise)**: endpoint daemon captures ES/unified-log events → local analysis (+ optional AI) → gRPC stream to server → PostgreSQL → dashboard/REST consumers.
- **Dashboard** (`aftersec-dashboard/`): Next.js 16 + NextAuth + Tailwind web UI; it has its own CLAUDE.md/AGENTS.md.
- **Other**: `macapp/` (Swift/SwiftUI mac app sources and AfterSec.app), `afterseclib/` (c-shared library entry), `tests/integration/` (enrollment, scan sync, threat intel), `docs/` (architecture docs), `monitoring/`.
