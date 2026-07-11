# FABLE_TODO — AfterSec fail-open security defects

Handoff for a Fable planning pass. Fable diagnoses + plans; Opus hardens the
handlers. Read `~/development/ads-fable-utils/SECURITY-RULES.md` FIRST — each area
needs a `Threats:` note and must fail closed.

## Context (2026-07-11 audit)
A claimed "6-fix batch" was audited. Three of the named fixes — **SecurityOps
stubs, EnrichIP nesting, and a July gRPC data-loss fix — DO NOT EXIST** in this repo
(pickaxe empty across all branches/history/stash/worktrees; no matching commits
since 2026-07-01). Do not go looking for them. Instead, the audit found REAL
fail-open bugs and left **honest failing tests** in place at commit `e4070ae`:
- `pkg/server/grpc/faildclosed_test.go`
- `pkg/threatintel/enrich_ip_test.go`

`go test ./pkg/server/grpc` is **RED by design** until the handlers below are
hardened. `pkg/threatintel` is green (5 passing tests locking in correct behavior).

## The defects (with tests already written)
1. **`pkg/server/grpc/server.go:116-125` — `StreamEvents` telemetry data loss +
   false ack.** On a full `eventQueue` it silently drops the event (non-blocking
   `select { default: /* drop */ }`) AND still counts it in the returned
   `StreamAck.EventsProcessed`. So the client is told N processed while <N were
   retained. Violates SECURITY-RULES "no swallowed data."
   Fix: apply backpressure or durably retain; NEVER ack an event that was dropped.
   Failing tests: `TestStreamEvents_DoesNotAckDroppedEvents` (+ related).
2. **`pkg/server/grpc/server.go:75-83` — `Enroll` fail-open stub.** Returns
   unconditional `Success:true` with a hardcoded `AccessToken:"stubbing_token_123"` —
   enrolls any/empty caller and hands out an identical static token every time.
   Fix: validate identity; issue a per-enrollment `crypto/rand` token (SECURITY-RULES
   rule 1). Failing tests: `TestEnroll_RejectsUnidentifiedRequest`,
   `TestEnroll_DoesNotIssueStaticToken`.

## Flagged, not yet tested (add negative tests + fix)
- `pkg/darkscan/daemon_client.go:226` — comment literally says "default to allow for
  fail-open security." Fail-open in an EDR is a hole. Should fail closed.
- `pkg/server/api/rest/router.go:208` — Redis-error path fails open.
- `pkg/threatintel/darkapi.go:316` — builds the IOC lookup URL with an unescaped
  `value` (needs `url.PathEscape`); injection / malformed-lookup risk.

## Definition of done
- The 3 failing gRPC tests go GREEN by hardening the handlers — NOT by weakening the
  tests. `go test ./pkg/server/grpc` clean.
- Each flagged fail-open above gets a negative test proving the bad case is denied,
  then a fail-closed fix.
- No `test.skip`, no stubs. Toolchain note from the audit: `go` is asdf-shimmed with
  no version set; use `/usr/local/bin/go` (satisfied the `go 1.25.7` directive).
- Author commits Ryan Coleman, no AI attribution.
