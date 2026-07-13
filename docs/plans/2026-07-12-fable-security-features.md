# FABLE Security Features Implementation Plan

> **For Codex:** Use `${SUPERPOWERS_SKILLS_ROOT}/skills/collaboration/executing-plans/SKILL.md` to implement this plan task-by-task.

**Goal:** Deliver all 15 FABLE security features as tested, fail-closed capabilities integrated with AfterSec's existing endpoint, gRPC, storage, threat-intelligence, and server layers.

**Architecture:** Build the integrity and identity foundations first, then sensors, self-defense, enforcement, and fleet analytics. Endpoint capabilities expose narrow platform interfaces with Darwin/Linux implementations; server features consume authenticated, durable telemetry and persist tenant-scoped state. Every security boundary carries a `Threats:` note, negative tests, bounded inputs, and explicit failure behavior.

**Tech Stack:** Go 1.25.7+, gRPC/protobuf, SQLite WAL, PostgreSQL, Redis, Ed25519, macOS Endpoint Security/Network Extension/Disk Arbitration, Linux eBPF/fanotify/nftables/udev, Sigma, OSV/KEV/EPSS.

---

## Global delivery rules

- Use `/usr/local/bin/go`; set `GOCACHE=/private/tmp/aftersec-go-cache` in sandboxed runs.
- For each behavior: add one negative test, run it red, implement minimally, run focused tests green, then run `go test ./...`.
- Run platform-specific compilation/tests where build tags permit; hardware/privileged adapters require fake-kernel contract tests.
- Never weaken the existing fail-closed tests. Never log credentials, raw evidence, or action tokens.
- Commit only at verified tranche boundaries; author remains Ryan Coleman with no AI attribution.

### Task 1: Hash-chained durable event journal (#8)

**Files:**
- Create: `pkg/eventjournal/journal.go`
- Create: `pkg/eventjournal/journal_test.go`
- Modify: `pkg/server/grpc/server.go`
- Modify: `pkg/server/grpc/faildclosed_test.go`
- Modify: `pkg/client/grpc.go`
- Test: `pkg/client/grpc_test.go`

1. Write failing tests for SQLite WAL persistence across reopen, `SHA-256(prev_hash || canonical_event)` continuity, tamper/gap detection, maximum-size rejection, and cursor advancement only through acknowledged sequence numbers.
2. Run `go test ./pkg/eventjournal ./pkg/server/grpc ./pkg/client` and confirm failures describe missing journal behavior.
3. Implement a transaction-backed journal with parameterized SQL, a configurable byte/record cap, canonical protobuf bytes, chain verification on open/read, and explicit `ErrFull`/`ErrTampered` errors.
4. Inject a journal interface into the gRPC server. Append and commit before incrementing `EventsProcessed`; return a failed-precondition/resource-exhausted response on tamper/full.
5. Add client store-and-forward: read unsent rows in sequence, stream them, and mark exactly the acknowledged prefix synced in one transaction.
6. Run focused tests, `go test -race ./pkg/eventjournal ./pkg/server/grpc ./pkg/client`, `git diff --check`, and the full suite.

### Task 2: Hardware-backed attestation enrollment (#9)

**Files:**
- Create: `pkg/attestation/types.go`, `verifier.go`, `darwin.go`, `linux.go`
- Create: corresponding `*_test.go` and fake verifier
- Modify: `api/proto/aftersec.proto` and regenerate `pkg/api/grpc/*`
- Modify: `pkg/server/grpc/server.go`, `pkg/client/grpc.go`
- Modify/Create: `pkg/server/repository/enrollment.go` and migrations

1. Test rejection of empty identity, invalid/expired attestation, wrong nonce/PCR policy, replayed enrollment code, and verifier outage.
2. Add org-scoped, hashed, single-use enrollment codes with expiry and transactional consumption.
3. Define attestation verifier/provider interfaces; implement Secure Enclave and TPM adapters behind platform tags, with deterministic contract fakes.
4. Issue a short-lived client certificate plus CSPRNG refresh token only after code and attestation verification; store only token fingerprints/hashes.
5. Test replay races, credential uniqueness, expiry, and audit records; run race and integration suites.

### Task 3: Process-attributed network sensor (#7)

**Files:**
- Create: `pkg/netsensor/{sensor,flow,linux,darwin}.go` and tests
- Modify: `pkg/edr/events.go`, `api/proto/aftersec.proto`, endpoint startup wiring

1. Specify bounded flow events: process identity, UID, local/remote tuple, protocol, bytes, start/end, and attribution confidence.
2. Test malformed/oversized kernel events, queue saturation, missing process attribution, shutdown, and denied sensor initialization.
3. Implement Linux eBPF and macOS NEFilter adapters behind a common sensor interface; adapters fail startup when policy requires visibility and attachment fails.
4. Stream flow events through the durable journal; integration-test sequence and restart behavior.

### Task 4: DNS threat analytics (#6)

**Files:**
- Create: `pkg/dnsanalytics/{capture,features,model,detector}.go` and tests
- Modify: `pkg/threatintel/correlator.go`, network sensor wiring

1. Test IDNA/homoglyph normalization, length limits, malformed labels, DGA scoring boundaries, process attribution, and threat-intel outage handling.
2. Implement local entropy/n-gram scoring and bounded capture adapters; enrich via threat intelligence without making cloud availability a bypass.
3. Emit signed/durable detections and composite DGA-plus-persistence alerts.

### Task 5: Agent self-protection (#11)

**Files:**
- Create: `pkg/selfprotect/{policy,watchdog,linux,darwin}.go` and tests
- Modify: heartbeat persistence/correlation on server

1. Test unsigned writes, unload/stop attempts, entitlement loss, stale heartbeats, clock skew, and watchdog failure.
2. Implement endpoint authorization hooks and a server-side heartbeat state machine; silence becomes an incident after a configured, tested deadline.
3. Preserve control-plane recovery while denying unauthorized agent mutation.

### Task 6: Real-time file integrity monitoring (#10)

**Files:**
- Create: `pkg/fim/{monitor,event,linux,darwin}.go` and tests
- Modify: durable event and correlator wiring

1. Test critical-path canonicalization, symlink escapes, rename/delete, writer attribution, content limits, overflow, and watcher failure.
2. Implement ES/fanotify adapters and bounded before/after capture; fail policy-required startup if watches cannot attach.

### Task 7: Signed Sigma rule packs (#12)

**Files:**
- Create: `pkg/detection/{pack,verify,compile,engine}.go` and tests
- Modify: `pkg/telemetry/sigma.go`, gRPC distribution and server repository

1. Test wrong key, tampering, rollback, expiry, malformed/oversized packs, empty packs, and compiler failure.
2. Verify Ed25519 signatures before compilation; atomically activate a version and retain the last valid pack on error while alerting.

### Task 8: Host network quarantine (#1)

**Files:**
- Create: `pkg/response/{quarantine,linux,darwin}.go` and tests
- Modify: command protocol/dispatcher and audit storage

1. Test invalid control endpoint, partial rule application, verification failure, idempotent quarantine, and unauthorized release.
2. Implement nftables and `pf` transactional adapters. Apply block rules first; a control-channel allow-rule verification failure keeps containment in place and alerts.

### Task 9: Live response remote triage (#2)

**Files:**
- Create: `pkg/response/{action,token,executor,audit}.go` and tests
- Modify: command protocol, `pkg/forensics`, PostgreSQL migrations/RLS

1. Test RBAC denial, wrong endpoint/tenant/action audience, expiry, replay, bad Ed25519 signature, output overflow, and append-only audit tampering.
2. Add signed single-use action tokens, allowlisted executors, bounded collection, and hash-linked tenant audit records.

### Task 10: Ransomware behavioral shield (#3)

**Files:**
- Create: `pkg/ransomware/{canary,detector,enforcer,linux,darwin}.go` and tests

1. Test canary tampering, entropy/rename bursts, false-positive boundaries, queue overflow, suspension failure, and policy outage.
2. Suspend first through ES AUTH or SIGSTOP/fanotify permission events, persist evidence, then request operator/AI disposition.

### Task 11: Binary authorization (#4)

**Files:**
- Create: `pkg/binaryauth/{policy,cache,verify,linux,darwin}.go` and tests

1. Test unsigned/corrupt/expired/rollback policies, unknown binaries, cache corruption, fetch outage, hash race, and learn-mode boundaries.
2. Enforce the last signed cached policy; when no policy has ever existed, enter explicit audited learn mode rather than silently allowing.

### Task 12: USB/removable media control (#5)

**Files:**
- Create: `pkg/devicecontrol/{policy,event,linux,darwin}.go` and tests

1. Test unknown classes, missing serials, spoofed IDs, policy outage, mount races, and read-only enforcement failure.
2. Implement udev/authorization and IOKit/Disk Arbitration adapters; deny unknown devices under block policy and journal every decision.

### Task 13: Exploit-aware vulnerability prioritization (#13)

**Files:**
- Create: `pkg/vulnpriority/{feeds,score,service}.go` and tests
- Modify: `pkg/patchmgr`, `pkg/threatintel`

1. Test signed/feed freshness, malformed CVEs, KEV/EPSS conflicts, unavailable feeds, and deterministic ranking ties.
2. Join package CVEs, KEV, EPSS, execution, and listening-flow facts into explainable per-endpoint rankings; stale feed state lowers confidence and alerts rather than erasing known risk.

### Task 14: Fleet-wide lateral movement correlation (#14)

**Files:**
- Create: `pkg/fleetcorrelation/{model,engine,store}.go` and tests
- Modify: `pkg/threatintel/correlator.go`, PostgreSQL migrations/RLS

1. Test tenant isolation, out-of-order/duplicate events, clock skew, cardinality limits, partial fleet visibility, and database failure.
2. Correlate SSH pivots, hash fan-out, and credential fan-out in bounded windows; persist composite evidence and deliver fleet context to SWARM AI.

### Task 15: CIS compliance packs and signed evidence (#15)

**Files:**
- Create: `pkg/compliance/{control,pack,runner,evidence,sign}.go` and tests
- Modify: `pkg/scanners`, server scheduling/export endpoints

1. Test unsigned/rollback packs, unsupported controls, command timeouts, oversized output, tenant isolation, evidence tampering, and wrong signing key.
2. Implement versioned CIS packs for supported macOS/Linux releases, bounded raw evidence capture, scoring, scheduling, and Ed25519-signed timestamped exports.

### Task 16: Final integration and release gates

1. Run `/usr/local/bin/gofmt` over changed Go files and `git diff --check`.
2. Run `go test -race` on pure-Go security packages and `go test ./...` with localhost access for integration tests.
3. Run platform compile matrices, protobuf compatibility tests, migrations against empty and upgraded databases, and security scanners from `security/README.md`.
4. Confirm every feature has `Threats:` documentation, negative tests, bounded inputs, explicit fail-closed semantics, and operator-visible errors.
5. Update `FABLE_TODO.md` only for behavior proven by the gates above; create one authored commit per independently revertible tranche.
