# Aftersec merge review — September 16, 2026

Reviewed the pending daemon authorization, YARA, executable identity, transport,
compliance, budget, CLI, DNS, build and Windows scanner changes alongside the
shared DarkAPI reporting branch. The branch descends from main without divergent
commits at review time.

## Ready to merge

- Explicit ALLOW-only detonation verdicts; panic and scanner errors deny execution.
  Authorization responses do not cache path-dependent decisions.
- Verified TLS for management REST/gRPC; missing/invalid configuration no longer
  silently falls back to standalone mode. REST and gRPC addresses are separate.
- Descriptor-based executable identity checks and explicit size rejection.
- Bounded YARA output/deadline and independent rule-file scans; stderr alone does
  not constitute a malware match. Audit-write failures propagate.
- Compliance evidence reflects exit status; bounded direct-argv executor with
  timeout and output-limit tests. Equal signed pack versions can be reverified.
- Serialized budget rollover; negative usage rejected. Linux heuristic training
  reports unavailable rather than inventing a trained model.
- IPv4-mapped resolver addresses and TCP/UDP 443/853 classification covered.
- Minimal read-only Windows Defender/firewall scanner, CI and platform build flags.

## Limits retained in the platform guide

Native privileged sensor validation requires appropriate OS runners, entitlements
and privileges. Path-based scanning is not an immutable-vnode authorization chain.
Compliance controls still require verified signed packs and an operator workflow.
REST bearer-token lifecycle needs deployment review. The full Unix daemon is not
a Windows port; the Windows scanner is a separate component. The local DarkScan
module replacement remains machine-specific; CI remaps it using repository secrets.
No production deployment is included in this merge.
