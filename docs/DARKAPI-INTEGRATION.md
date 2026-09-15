# Aftersec and darkd: shared endpoint evidence

## Six implementation phases

1. Add an app registry and preserve existing canonical `darkd_devices.device_id` values.
2. Add single-use, owner-bound enrollment and distinct credentials for each app.
3. Add Aftersec's authenticated client and independent durable SQLite upload queue.
4. Normalize evidence and expose bounded, tenant-scoped cross-app associations.
5. Add the Endpoints console for pairing, app status, reporting coverage and inspection.
6. Verify migration replay, authentication, retries, correlations and the browser workflow.

## Identity and enrollment

Open `/console/endpoints`. Create an Aftersec token and select an existing darkd
host. Aftersec receives exactly that host's device ID, with its own API key. To
start with Aftersec, select **Create a new host**, enroll it, then mint a darkd
token bound to the resulting host. Existing darkd credentials keep working.

The server does not infer identity from hostname, MAC address or client-supplied
hardware IDs. The owner explicitly chooses which host to pair. Enrolling against
an already-active app returns 409; revoke that app before replacing its key.
Revoking one app leaves its sibling working. Revoking the host blocks both.
Recorded evidence remains accessible after revocation. This flow does not merge
two already-existing host records or rewrite their historical evidence.

Tokens (`ept_`) expire after 24 hours, are single-use and app-specific, and are
stored only as hashes. The console displays a newly created token once.
Concurrent redemption has one winner. Account read keys cannot mint/revoke;
console sessions and write/admin keys can. Agent credentials cannot manage hosts
or read another app's events. Legacy darkd `dde_` tokens remain supported.

On the host, set `AFTERSEC_DARKAPI_ENROLLMENT_TOKEN` privately, then run:

```sh
aftersec cloud enroll --credentials /secure/path/aftersec-darkapi.json
aftersec cloud status --credentials /secure/path/aftersec-darkapi.json
```

Set `AFTERSEC_DARKAPI_CREDENTIALS` to that absolute file path in the `aftersecd`
service environment and restart. The credential file is created exclusively with
0600 permissions. It must be accessible to the daemon's service account. Use a
directory accessible only to that account. Clear the enrollment environment
variable after enrollment. `https://darkapi.io/api/` normalizes to
`https://api.darkapi.io`; other base URLs must be HTTPS roots. Redirects are refused.
If enrollment succeeds but local credential persistence fails, revoke the app
from the console and issue a replacement token; the original token is consumed.

For darkd, use its existing `darkapi device enroll --credentials ...` command with
`DARKAPI_ENROLLMENT_TOKEN`, then configure `api.darkapi.credential_file` and
`api.darkapi.telemetry_enabled: true` in darkd.yaml. The apps use separate files.
Darkd's local event-store endpoint identity is preserved as source evidence;
DarkAPI's authenticated device ID is authoritative for grouping and ownership.

## API contract

| Method | Path | Authentication / result |
| --- | --- | --- |
| POST | `/v1/endpoint-enrollment-tokens` | Account write/console; `{name, app, device_id?}`; 201 once-only token |
| GET | `/v1/endpoint-enrollment-tokens` | Account read; newest 100 token metadata records, never secrets |
| DELETE | `/v1/endpoint-enrollment-tokens/{token_uuid}` | Account write/console; revoke unused token |
| POST | `/api/v1/aftersec/enroll` | Enrollment token in JSON; 201 `{success, app, device_id, api_key}` |
| POST | `/v1/devices/enroll` | Existing darkd endpoint also accepts app-specific tokens |
| POST | `/api/v1/aftersec/heartbeat` | Aftersec `X-API-Key` + `X-Device-ID`; capabilities/contact |
| GET | `/api/v1/aftersec/config` | Aftersec credentials; schema, limits and app-scoped config |
| POST | `/api/v1/aftersec/telemetry` | Aftersec credentials; atomic batch; 202 exact accepted UUIDs |
| GET | `/v1/devices/{id}/agents` | Account read; per-app contact, capabilities and revocation status |
| DELETE | `/v1/devices/{id}/agents/{app}` | Account write/console; revoke one app |
| GET | `/v1/devices/{id}/events` | Account read; shared timeline |
| GET | `/v1/devices/{id}/events/{app}/{uuid}` | Account read; original payload and normalized fields |
| GET | `/v1/devices/{id}/events/{app}/{uuid}/related` | Account read; opposite-app associations |
| GET | `/v1/devices/{id}/reports` | Account read; latest evidence for each category and app |

Telemetry accepts 1–100 events and a maximum 1 MiB request. Each event has a UUID
`event_id` and an `event` object with `type`, `source`, `severity`, optional
`category`, timezone-qualified `time`, object `data`, optional UUID
`correlation_id`, and optional object `entities` (at most 20 fields). Body
`device_id` and event `system_id`, if present, must match authenticated identity.
Ownership and app provenance always come from authentication.

```json
{"device_id":"dev_example","events":[{
  "event_id":"ed73b11f-c576-47f1-8c4d-a4d31f2c6a7b",
  "event":{"type":"network.connection","source":"aftersec",
    "category":"network_flows","severity":"info",
    "time":"2026-09-15T12:00:00Z","data":{"remote_ip":"203.0.113.9"}}
}]}
```

Identical retries are accepted without duplication; reusing a UUID with changed
content returns 409. A malformed event rolls back the whole batch. Invalid
credentials return 401; unauthorized account mutations 403; inaccessible records
404; invalid inputs 400; oversized Aftersec bodies 413; unavailable storage 503.
The Go client only acknowledges an exact successful device-and-event-ID response.

Timeline query parameters: `app`, `category`, `severity`, `hours` (1–744, default
24), `limit` (1–100, default 50), and `before` (the returned `next_cursor`). Related
events are limited to 100; default 50; `truncated` reports additional matches.
All console data is fetched through the same-origin account bridge with server
session credentials. Device ingestion is not exposed through that bridge.

## Reporting scope: requested areas plus 18 additional categories

These are evidence channels over the actual enabled collectors, not assertions
that every sensor exists or runs on every OS. The new exporter records events
passing through the daemon storage manager and posture findings saved through it.
Reports absent from a host remain **unknown**. Latest observations older than
24 hours are **stale**. A reported failing check is still failing.

| Category | Evidence source / coverage |
| --- | --- |
| monitoring | New exporter queue depth, bytes and capacity metrics |
| telemetry | Existing storage-manager event stream, preserving source/type/data |
| patches | Existing patch/update posture findings; no new patch execution |
| host_ids | Existing intrusion, rootkit and detection events |
| firewall | Existing firewall posture findings; rule changes can use explicit category |
| process_lineage | Existing process exec/exit events, PID/PPID and executable evidence |
| network_flows | Existing process-attributed network sensor flows |
| dns | Existing DNS/DoH/correlation events |
| file_integrity | Existing FIM and critical path write evidence |
| binary_signatures | Existing binary authorization and signature decisions |
| ransomware | Existing canary/shield detection and suspension records |
| device_control | Existing removable-media decisions |
| persistence | Existing persistence detections when journaled |
| vulnerabilities | CVE/vulnerability events when journaled; patch findings remain patches |
| compliance | Existing saved posture findings and CIS references |
| scan_findings | Existing YARA, malware, memory and container findings |
| self_protection | Existing tamper/agent mutation records |
| sensor_health | Explicit collector health events/capabilities; missing collectors are unknown |
| software_inventory | Existing darkd software inventory; Aftersec can submit explicit inventory events |
| policy_state | New safe startup configuration and local policy-save records |
| agent_resources | New runtime OS/architecture, heap and goroutine metrics |
| response_audit | Existing response/quarantine/remediation events when journaled |
| configuration_drift | New persisted comparison of safe configuration fingerprints across restarts |

The backend can accept explicit categories for new adapters without changing host
identity or app authentication. Runtime capabilities use `active`, `disabled`,
`unavailable`, `error`, or `unknown`; the default heartbeat only asserts the two
collectors it owns (`telemetry`, `agent_resources`). Startup enabled flags describe
requested policy and deliberately do not claim sensor health. Console capabilities
and evidence freshness are separate views.

## Cross-app links

Both events must belong to the same owner and canonical host, come from opposite
apps, and fall within 24 hours of each other. Observation times are preferred;
legacy evidence without source time uses reception time. A shared correlation UUID
or matching SHA-256, remote IP, domain, or boot identity plus PID and valid process start time makes
an association. Different JSON naming styles and nested connection/process/identity
records are normalized. A flow's start time is not a process start time. Hostnames
and PID alone are never used. IP/domain associations can be broad; the UI shows the
matching identifiers and explicitly avoids claiming causation or maliciousness.

## Durability, limits and operations

Aftersec uses a separate `darkapi-outbox.sqlite` beside its credential file,
independent of the existing enterprise exporter and its synced flags. Records get
stable UUIDs before network delivery, survive restart, and remain until exact
server acknowledgment. Queue rows are bound to the device that created them and
are never reassigned after enrollment changes. The loop polls its durable source
once per second, with 30-second HTTP timeouts and up to 20 upload batches per cycle.
Heartbeat/resource reports run every 30 seconds. Retryable failures use bounded
exponential backoff with jitter and honor Retry-After (up to one hour).
Individual events are limited to 256 KiB; pending plus quarantined payloads to
100 MiB. Capacity/storage errors preserve the source cursor and pending evidence.
Permanent rejected events move to quarantine while valid records continue;
authentication, rate-limit and server failures remain pending.

The SQLite journal is the replayable telemetry source. DarkAPI imports it using
its own persistent cursor, atomically committing outbox rows with cursor updates.
A crash after journal append but before the secondary telemetry projection is
recoverable. Saved posture has its own cursor. Enterprise synced flags are neither
read nor changed. Producers must still handle failed source writes. Pre-journal
SQL-only telemetry is not reconstructed by this backfill.

```sh
aftersec cloud queue --credentials /secure/path/aftersec-darkapi.json
aftersec cloud backfill --source /existing/aftersec/storage --credentials /secure/path/aftersec-darkapi.json
aftersec cloud retry EVENT_ID --credentials /secure/path/aftersec-darkapi.json
```

Backfill queues historical journal/posture; the running daemon handles delivery.
Stable source event IDs deduplicate replay. Invalid source JSON remains locally
quarantined and cannot be blindly requeued; journal hash-chain corruption stops
import. Queue status reports queued, accepted, rejected-attempt and pending counts.
Quarantined payloads consume capacity and require operator investigation.

The v2 envelope adds schema, boot/agent version, stream/sequence, collection status,
typed entities and explicit facts. Missing historical provenance stays unknown.
DarkAPI enqueues analysis transactionally and provides detections, evidence,
analysis status and bounded replay in the Endpoints console. Deterministic rules
require sufficient source facts from both apps; they do not create missing sensor
coverage or statistical anomaly baselines. See backend `DARKAPI_NG_PLAN_SEPT26.md`.

Known credential-shaped object fields are redacted recursively, including nested
arrays. This is not general-purpose DLP: source free text, command arguments and
finding values can contain sensitive information. Configure source collection and
account access accordingly. No remote response commands are executed by this
integration. The config endpoint is readable, not a new remote execution channel.

macOS daemon/CLI and transport tests run locally. Linux uses existing Aftersec
collectors and this same contract; Windows needs its existing native-agent work
and an appropriate SQLite/CGO build plus protected service-account directory ACLs.
This change does not turn the Unix daemon into a production Windows service.
Database retention/archival policy is still an operator responsibility; the new
migration adds no destructive cleanup.

## Rollout

Apply migrations before starting the updated API (the repository migration runner
orders this after daemon reliability and console migrations), then deploy API and
console, then opt individual Aftersec hosts in. Do not deploy clients against an
older backend that lacks the new routes. Re-running the runner skips applied
migrations; schema SQL also tolerates replay. The existing SOAR `endpoint_agents`
table is separate: this integration uses `darkapi_device_apps` and
`darkapi_device_events` to avoid changing that contract.

Backend validation lives in the darkapi.io repository: `tests/api/test_endpoint_agents.py`, console and daemon reliability suites, and `dashboard/tests/endpoints-browser.cjs`. Aftersec validation is in `pkg/darkapi` and `pkg/edr/events_json_test.go`. Browser fixtures are local only.
