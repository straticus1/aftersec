# Platform and security review

## Changes

- Execution authorization defaults to denial, including panic recovery, and no longer caches decisions across executions. Missing enterprise configuration, scanner errors, unknown/truncated/oversized detonation responses, and audit failures cannot grant execution.
- YARA runs each configured rule file with a five-second shared timeout and bounded output. Command failures propagate; diagnostic output cannot masquerade as a match.
- Executable inspection compares the opened file with the path, checks file metadata after provenance collection, and rejects files larger than 16 GiB. This reduces pathname races but does not provide kernel-level fd/vnode binding throughout all scanner phases.
- gRPC enrollment requires verified TLS. REST detonation uses the configured CA/client identity, requires HTTPS, and refuses redirects. Invalid configuration no longer silently falls back to standalone mode.
- Compliance has a bounded command executor. Exit zero means compliant; nonzero becomes a failed control, while execution failures/timeouts abort collection. Installed signed packs can be reverified at their active version.
- Known encrypted DNS resolver observations include IPv4-mapped addresses, UDP/443, and TCP/UDP 853. These are connection observations, not proof that the traffic contains DNS, and do not decrypt traffic.
- Budget rollover now uses an exclusive lock; negative token usage is rejected.
- The Linux heuristic backend returns an error for unavailable model training instead of reporting a fictitious saved model. Placeholder CLI commands now return nonzero status.
- Build script stops on failures and applies Apple compiler flags only to macOS targets.

## Minimal Windows support

Build with `./build.sh windows`, then run `bin/aftersec-windows.exe scan` on Windows. The standalone scanner checks Defender antivirus/real-time protection and all firewall profiles using Windows PowerShell. It emits JSON. Exit 0 means both checks passed, 1 means a failed or unavailable check, and 2 means a usage/platform error. Each command has a 15-second timeout and bounded output. It does not change system configuration.

`aftersec-windows report` posts that JSON, plus hostname, OS version, and last boot, to `POST /api/v1/inventory/windows` over TLS. The server records enrollment status `inventory` and does not issue a certificate, refresh token, or hardware quote. Remote actions against that row are refused. The signed bootstrap can deliver `aftersec-windows` for `windows`/`amd64` only.

This is a separate minimal scanner. The full CLI, daemon, Unix sensors, GUI and enforcement stack are not Windows ports. Native Windows CI was added for scanner tests and compilation; local cross-compilation does not establish runtime behavior on Windows.

## Enterprise configuration migration

Use separate gRPC and HTTPS REST addresses:

```yaml
server:
  address: security.example.com:9090
  detonation_address: https://security.example.com:8443
  tls:
    ca: /etc/aftersec/ca.pem
    cert: /etc/aftersec/client.pem
    key: /etc/aftersec/client-key.pem
```

Cleartext enrollment configurations now fail. REST authorization still uses the existing enrollment-token field; production enrollment-token versus REST access-token lifecycle needs an end-to-end deployment review.

## Remaining work and verification limits

- Privileged Linux fanotify/eBPF and macOS Endpoint Security/Network Extension enforcement require native hosts, privileges, signing and entitlements. Compilation/unit tests cannot certify those integrations.
- Path-based scanners still need a shared immutable file identity bound to the intercepted executable to eliminate races across every authorization phase.
- Compliance is a library with tests and a command executor, not yet an enrolled daemon control-pack scheduling/reporting workflow. Callers must verify signed packs before executing controls.
- CLI plugin/forensics/baseline/report/config/daemon/enroll/shell management commands remain unfinished and report errors. Existing separately implemented commands remain available.
- REST tier/AI usage reporting contains TODOs and hardcoded zero usage. Connecting a process-global tracker would misattribute tenant spend; durable tenant-scoped accounting remains needed.
- Linux advanced process-memory forensics and non-ONNX local model training remain unavailable.
- The Go module still uses a machine-specific local DarkScan replacement; fresh checkouts need that dependency mapped.
- Dashboard, GUI interaction, live server/database/external services, model inference, and signed native sensor installation require separate end-to-end validation.
- Local macOS linker warnings show native libraries built for newer macOS releases than the declared 11.0 target. Older macOS compatibility is not established by this build.

## Verification results

- Passed: Linux amd64 and arm64 cross-compilation of `./cmd/aftersecd/... ./cmd/aftersec/... ./pkg/...` with CGO disabled.
- Passed: `./build.sh windows` produces `bin/aftersec-windows.exe`.
- Passed: focused macOS tests for daemon authorization, client TLS/configuration, YARA plugins, executable inspection, compliance executor, and the Windows scanner.
- Passed: budget concurrency regression with the Go race detector.
- Passed: shell syntax and Git whitespace checks.
- Passed: final `go test ./...` on macOS (Go 1.25.7), including GUI/library compilation and integration package. Credential-dependent external threat-intelligence tests may skip; this is not a live fleet deployment test.

Commands used `ASDF_GOLANG_VERSION=1.24.6` to select the installed launcher, which automatically used the module-required Go 1.25.7 toolchain. No toolchain version file was added to the repository.
