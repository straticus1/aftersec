# AfterSec macOS Network Extension providers

These sources are compiled as two separate macOS extension targets:

- `AfterSecFlowFilterProvider` (`NEFilterDataProvider`)
- `AfterSecDNSProxyProvider` (`NEDNSProxyProvider`)

Both targets require Apple Network Extension entitlements and a signed
provisioning profile. They fail startup when the authenticated event sink is
missing and bound every emitted record to a 16 KiB JSONL frame. The host daemon
must validate process attribution before journaling; missing attribution is a
deny condition.
