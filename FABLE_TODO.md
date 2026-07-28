# FABLE_TODO — AfterSec fail-open security defects

Handoff for a Fable planning pass. Fable diagnoses + plans; Opus hardens the
handlers. Read `~/development/ads-fable-utils/SECURITY-RULES.md` FIRST — each area
needs a `Threats:` note and must fail closed.

## Current status (2026-07-28)

The July 11 defect list is retained below as audit history. All five named
fail-open defects are now fixed: telemetry never drop-and-acks, enrollment
requires attested identity, DarkScan real-time errors block, rate-limiter errors
deny, and IOC path values are escaped. The focused gRPC and threat-intelligence
test suites are green.

This pass also completed the endpoint integration tranche:

- **#2 Live Response:** the REST endpoint now derives tenant and role only from
  validated JWT claims, verifies live endpoint ownership, mints a short-lived
  endpoint-bound Ed25519 action token, and dispatches only `REMOTE_ACTION`.
  Missing signing configuration fails closed. Dispatches and results are
  persisted as append-only hash-linked lifecycle records.
- **#7 Network Sensor:** the macOS Network Extension now extracts audit-token
  PID/UID attribution, app identity, endpoints, and protocol; a permission-
  checked bounded JSONL backend feeds validated flows into daemon telemetry.
  Sink/write/persistence failures stop a required sensor. Linux now loads a
  process-attributed CO-RE TCP backend. Remaining: signed extension/BPF object
  packaging and UDP byte/duration coverage.
- **#11 Self-Protection:** server heartbeats now feed the silence tracker;
  clock-skewed heartbeats are rejected and missed deadlines create durable,
  tenant-isolated `agent_silence_incidents`. ES authorization and Linux BPF-LSM
  hooks enforce protected mutations, and the separately supervised local
  watchdog restarts a missing agent. Remaining: native service-stop and
  entitlement-revocation authorization.

### Active backlog by feature

- **#1:** platform integration tests for quarantine/release.
- **#2:** complete; add PostgreSQL integration coverage for concurrent audit
  writers.
- **#3:** add native rename-event counters to the attached canary shield.
- **#4:** complete; server-side policy distribution remains a fleet enhancement.
- **#5:** complete core discovery/wiring; add mount-race integration tests.
- **#6:** add TCP/DoH capture, trained n-gram scoring, and NRD enrichment.
- **#7:** package/sign the extensions and BPF objects; add UDP and byte/duration
  accounting.
- **#8:** complete.
- **#9:** add production Secure Enclave and TPM quote adapters.
- **#10:** add rename/delete before/after evidence.
- **#11:** add native service-stop authorization and entitlement-revocation
  detection.
- **#12:** replace unsigned heartbeat-delivered Sigma YAML with signed,
  versioned, rollback-protected packs.
- **#13:** ingest verified KEV/EPSS feeds and join rankings to live runtime
  observations.
- **#14:** connect the fleet correlation engine to durable server telemetry and
  alert persistence.
- **#15:** ship full OS-versioned CIS packs, scheduling, and signed evidence
  export.

## Context (2026-07-11 audit)
A claimed "6-fix batch" was audited. Three of the named fixes — **SecurityOps
stubs, EnrichIP nesting, and a July gRPC data-loss fix — DO NOT EXIST** in this repo
(pickaxe empty across all branches/history/stash/worktrees; no matching commits
since 2026-07-01). Do not go looking for them. Instead, the audit found REAL
fail-open bugs and left **honest failing tests** in place at commit `e4070ae`:
- `pkg/server/grpc/faildclosed_test.go`
- `pkg/threatintel/enrich_ip_test.go`

These tests were originally red by design. They are now green and remain as
regression coverage.

## Resolved defects (tests retained)
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

## Resolved audit flags

- `pkg/darkscan/daemon_client.go` blocks on real-time scan failure.
- `pkg/server/api/rest/router.go` returns 503 when Redis cannot establish a
  rate-limit decision.
- `pkg/threatintel/darkapi.go` escapes IOC route components.

## Original definition of done — satisfied
- The 3 failing gRPC tests go GREEN by hardening the handlers — NOT by weakening the
  tests. `go test ./pkg/server/grpc` clean.
- Each flagged fail-open above gets a negative test proving the bad case is denied,
  then a fail-closed fix.
- No `test.skip`, no stubs. Toolchain note from the audit: `go` is asdf-shimmed with
  no version set; use `/usr/local/bin/go` (satisfied the `go 1.25.7` directive).
- Author commits Ryan Coleman, no AI attribution.

---

# Feature backlog — 15 new security features (designed 2026-07-12)

Designs grounded in the existing architecture. Every feature follows the house
rule: fail closed, never swallow data, negative tests required. Features **#8**
and **#9** are the durable architectural fixes for defects #1 and #2 above —
but the minimal hardening pass (backpressure + real token issuance) should land
FIRST; these are the follow-on architecture, not a reason to wait.

## Response & Containment

1. **Host Network Quarantine.** Server-initiated containment: isolate an
   endpoint while keeping the mTLS gRPC control channel alive for
   un-quarantine + evidence streaming. macOS `pf` anchor rules, Linux
   `nftables` priority-override table. New `pkg/response`, triggered over the
   existing gRPC stream. Threats: active C2, ransomware spread, live exfil.
   Fail-closed: if the control-channel allow-rule can't be verified after
   applying the block set, keep the block set anyway.

   **Status (2026-07-12): enforcement foundation implemented.** A fail-closed,
   idempotent quarantine state machine plus macOS `pf` and Linux `nftables`
   adapters retain containment when control-channel verification fails and
   require explicit authorization for release. **Update (2026-07-28):** live
   server token minting, REST dispatch, system runner, and daemon command-loop
   wiring are implemented, and dispatch/result lifecycle records are durable.
   Platform quarantine/release integration tests remain.

2. **Live Response Remote Triage.** Audited remote actions (kill process,
   collect file, pull memory region, list persistence) reusing
   `pkg/forensics` collectors. Per-command server-side RBAC; hash-logged
   append-only audit table (PostgreSQL, RLS per-tenant); endpoint verifies a
   server-signed action token before executing. Threats: IR at distance +
   insider abuse of the feature itself. Fail-closed: unverifiable signature or
   expired token → refuse and alert (the anti-pattern at
   `darkscan/daemon_client.go:226` is the thing to never do here).

   **Status (2026-07-12): authorization and audit foundation implemented.**
   Endpoint/action/tenant-bound Ed25519 tokens enforce expiry, replay denial,
   action allowlists, and bounded output. The endpoint command processor accepts
   only signed `REMOTE_ACTION` envelopes; audit records are hash-linked, and the
   PostgreSQL schema is append-only with forced tenant RLS. Server-side RBAC
   now propagates only validated JWT claims and mints short-lived Ed25519 action
   tokens after explicit role/action authorization and endpoint tenant-ownership
   verification. **Update (2026-07-28):** REST dispatch injection and bounded
   system/forensics runners are wired. Dispatch-requested and terminal result
   lifecycle records are now transactionally appended to the tenant-isolated,
   hash-linked PostgreSQL audit table.

3. **Ransomware Behavioral Shield with Canary Decoys.** Plant decoy files in
   user dirs; any process touching a canary is suspended immediately (ES AUTH
   verdict on macOS, SIGSTOP + fanotify permission events on Linux). Plus an
   entropy/rename-burst detector on write events already flowing through
   `pkg/edr`. Threats: mass-encryption ransomware, wipers. Fail-closed:
   suspend first, ask the AI/operator second.

   **Status (2026-07-28): native event attachment implemented.**
   Private CSPRNG-named decoys reject symlink directories; canary touches and
   rename/entropy bursts synchronously suspend through `SIGSTOP` before evidence
   recording. ES `AUTH_OPEN` and Linux fanotify open/write events now feed
   canary containment and durable telemetry. Rename-burst counters still need
   native rename-event coverage.

## Prevention

4. **Binary Authorization (Application Allowlisting).** Gate `AUTH_EXEC`
   (macOS ES) / `fanotify FAN_OPEN_EXEC_PERM` (Linux) against
   server-distributed policy: code-signing team ID / notarization on macOS,
   package provenance + hash on Linux. Ships with a learn mode that builds the
   allowlist from baseline. Reuses `pkg/forensics/codesign*`. Threats:
   unsigned droppers, renamed LOLBins. Fail-closed: policy fetch failure →
   enforce last signed cached policy; no policy ever seen → learn mode, never
   silent-allow.

   **Status (2026-07-28): policy and native authorization implemented.** Ed25519-signed,
   monotonically versioned policies reject tampering, expiry, rollback, invalid
   identities, and corrupt caches. The cache installs atomically with private
   permissions; no-policy state is explicit learn mode, while an expired last
   policy denies. ES `AUTH_EXEC`/fanotify execution permission events now run a
   race-checked SHA-256 authorization. macOS collects strict native code-signing
   identity and Linux records dpkg/rpm package provenance.

5. **USB & Removable Media Control.** Block/allow/read-only policies for mass
   storage: IOKit + DiskArbitration on macOS, udev + USBGuard-style
   authorized-device list on Linux. Device events (VID/PID, serial, volume
   hash) stream into the existing event pipeline. Threats: BadUSB, thumb-drive
   exfil, rogue HID. Fail-closed: unknown device class under "block" policy →
   deny mount and alert.

   **Status (2026-07-28): discovery and policy wiring implemented.** Linux
   consumes kernel udev netlink events; macOS enumerates removable `IOMedia`
   entries through the IOKit registry. The controller enforces deny/read-only/
   read-write decisions through the platform mounter and durably journals every
   outcome. Deployment must explicitly enable the disruptive block policy.

6. **Egress DNS Threat Analytics.** DNS query capture with process
   attribution (macOS: NEDNSProxy, unified-log fallback; Linux: eBPF kprobe /
   dnstap). Detect DGA domains (local entropy + n-gram model, no cloud
   dependency), newly-registered-domain lookups via `pkg/threatintel`,
   punycode homoglyphs. Feeds the correlator (DGA hit + new persistence item =
   high-severity composite). Threats: C2 beaconing, DNS tunneling.

   **Status (2026-07-28): native UDP capture and correlation implemented.** Strict IDNA/DNS
   normalization rejects malformed and oversized names; every query requires
   PID/process attribution. Local entropy-based DGA scoring, punycode/homoglyph
   alerts, and optional threat-intelligence matches produce bounded results,
   while enrichment outages never suppress local detections. The macOS DNS
   proxy relays and emits attributed queries; Linux has a CO-RE `udp_sendmsg`
   probe. The daemon persists results and emits DGA-plus-persistence composites.
   TCP/DoH coverage, trained n-gram scoring, and newly-registered-domain
   enrichment remain.

## Visibility

7. **Process-Attributed Network Flow Sensor.** Per-connection telemetry
   (proc, user, remote addr, bytes, duration): eBPF TC/kprobes on Linux,
   `NEFilterDataProvider` on macOS. Flows land in the same gRPC event stream.
   Biggest current visibility gap — ES client sees exec/file/fork but not the
   network. Unlocks #6, #13, #14 and gives SWARM AI better per-event context.

   **Status (2026-07-28): macOS ingestion and Linux TCP capture implemented.** The Network
   Extension extracts audit-token PID/UID attribution and flow endpoints into a
   bounded sink. The daemon accepts only a trusted-permission sink, validates
   every flow, and stops a required pipeline on malformed input, saturation, or
   persistence failure. Linux loads a CO-RE kprobe backend for successful
   process-attributed IPv4/IPv6 TCP connects. Signed extension/object packaging
   and UDP/byte/duration accounting remain.

## Integrity & Self-Defense

8. **Hash-Chained Durable Event Journal (store-and-forward).** THE REAL FIX
   for defect #1 above. Replace the lossy in-memory `eventQueue` with an
   append-only, size-capped local journal (SQLite WAL or flat segments), each
   record chained `H(prev_hash ‖ event)`. `StreamAck.EventsProcessed` counts
   only server-durably-committed events; client advances its journal cursor
   only on ack. Server verifies chain continuity — a gap is itself a tamper
   alert. Threats: telemetry loss during outages; attacker deleting evidence
   between capture and upload. Fail-closed: journal full → backpressure the
   sensor + local alarm; NEVER drop-and-ack. Makes
   `TestStreamEvents_DoesNotAckDroppedEvents` green by architecture.

   **Status (2026-07-12): implemented.** Endpoint enterprise telemetry is
   persisted in SQLite plus a verified SHA-256 hash-chained WAL journal;
   tampering prevents reopen/sync, capacity fails closed, server acknowledgments
   follow deterministic durable commits, and clients advance only the exact
   acknowledged local prefix. Focused, race, integration, and full Go suites
   pass.

9. **Hardware-Backed Attestation Enrollment.** THE REAL FIX for defect #2
   above. Enrollment keypair in Secure Enclave (macOS) / TPM 2.0 (Linux); CSR
   + platform attestation (SE key attestation / TPM quote incl. Secure Boot
   PCRs) + org-scoped single-use enrollment code minted server-side. Server
   verifies attestation, issues a short-lived client cert for the existing
   mTLS channel + per-enrollment `crypto/rand` refresh token. Nothing static,
   nothing unconditional. Threats: rogue-agent enrollment, credential cloning
   (SE/TPM key can't leave hardware). Fail-closed: unverifiable attestation,
   replayed code, or empty identity → reject with audit event.
   `TestEnroll_RejectsUnidentifiedRequest` / `TestEnroll_DoesNotIssueStaticToken`
   are the floor of this story.

   **Status (2026-07-12): platform-neutral enrollment plumbing implemented.**
   Org-scoped expiring single-use codes, nonce-bound signed evidence, atomic
   PostgreSQL consumption/audit, short-lived CA-issued client certificates,
   CSPRNG refresh tokens, TLS 1.3 verification, Keychain/Linux-keyring credential
   storage, replay denial, and a fully verified development path are wired and
   tested. Native Secure Enclave attestation and Linux TPM 2.0 quote collection
   remain platform/hardware adapter work; production fails closed without an
   explicitly configured verifier and never falls back to software evidence.

10. **Real-Time File Integrity Monitoring.** Continuous watch on critical
    paths (`/etc`, launchd/systemd units, PAM, sudoers, agent's own
    config) via ES notify (macOS) / fanotify (Linux) — distinct from the
    point-in-time baseline/drift scan: catches the change as it happens with
    the writing process attached. Before/after content capture for small
    files. Threats: persistence installation, PAM backdoors, log tampering.

    **Status (2026-07-28): native write evidence implemented.** macOS pairs
    `AUTH_OPEN` with `NOTIFY_WRITE`; Linux pairs fanotify open with close-write
    and cancels read-only opens. Bounded before/after content and writer PID are
    durably recorded. Rename/delete evidence is still future hardening.

11. **Agent Self-Protection & Tamper Detection.** ES AUTH denies unsigned
    writes to `aftersecd` binaries/config/journal; detect `launchctl unload` /
    `systemctl stop` and TCC/entitlement revocation attempts; lightweight
    watchdog + SERVER-side "agent silenced" alert when heartbeats stop (server
    infers tamper from silence — endpoint can't be trusted to report its own
    death). Threats: competent malware kills the EDR first. Fail-closed: on
    the server, missing heartbeat = incident, not "probably asleep." Should
    precede shipping enforcement features attackers will want to disable.

   **Status (2026-07-28): endpoint and server protection implemented.** Validated
   heartbeats update a bounded tracker; skewed heartbeats are denied and missed
   deadlines create durable tenant-isolated incidents. macOS denies protected
   mutations with ES authorization; Linux ships a BPF-LSM inode guard for
   write/create/unlink/rename denial. A separate watchdog binary plus launchd
   and systemd service definitions restarts a missing agent. Native service-stop
   authorization and entitlement-revocation detection remain.

12. **Signed Detection-as-Code Rule Packs (Sigma support).** Rule engine in
    the event pipeline consuming Sigma rules compiled to native matchers,
    distributed as ed25519-signed versioned rule packs. Complements Starlark
    plugins (Starlark = custom logic; Sigma = community detections by the
    hundred). Threats: TTP detection gaps + supply-chain risk of the rule
    channel itself. Fail-closed: bad signature or malformed pack → keep
    previous pack + alert; never run unsigned rules, never silently run with
    zero rules.

## Fleet Intelligence

13. **Exploit-Aware Vulnerability Prioritization.** Join installed-package
    CVEs from `pkg/patchmgr` (OSV.dev), CISA KEV + EPSS feeds via
    `pkg/threatintel`, and runtime observations from the ES client (vulnerable
    binary actually executing? listening on a port? — via #7). Output: ranked
    per-endpoint "fix this first" list; exploited-in-the-wild CVE in a
    running, network-exposed process outranks a hundred dormant ones. Extends
    the planned patchmgr remediation phases 2/3.

14. **Fleet-Wide Lateral Movement Correlation.** Server-side (extends
    `pkg/threatintel/correlator.go` + PostgreSQL): stitch cross-endpoint
    sequences — SSH login on host B sourced from host A minutes after host A
    alerted; same file hash on N hosts in an hour; credential-use fan-out.
    Only the server sees the whole fleet. Threats: post-compromise spread,
    which single-endpoint EDR is structurally blind to. Composite detections
    feed SWARM AI with fleet context.

15. **CIS Benchmark Compliance Packs with Signed Evidence Export.** Extend
    `pkg/scanners` to full CIS Benchmark coverage (macOS + major Linux
    distros), scored per-control, scheduled fleet-wide, with an auditor-facing
    export: server-key-signed, timestamped evidence bundle mapping each
    control to raw check output. SOC 2 / ISO 27001 evidence collection — fits
    next to the Stripe billing tiers. Threats: config drift + evidence
    tampering after collection (hence signing).

## Suggested next build order

Package/sign native sensors (**#7**) → complete service-stop/rename hardening
(**#11/#3/#10**) → production hardware attestation (**#9**) → signed Sigma
distribution (**#12**) → fleet/feed/compliance integrations (**#13/#14/#15**).
