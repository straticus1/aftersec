package compliance

import (
	"crypto/ed25519"
	"strings"
	"time"

	"aftersec/pkg/core"
)

// PostureSchemaVersion is the signed snapshot format. It is not a CIS pack
// version and it does not mean the snapshot covers a full benchmark.
const PostureSchemaVersion uint64 = 1

const maxPostureRaw = 512

// PostureEvidence signs the scanner findings the endpoint actually produced.
// Remediation commands are not copied into the evidence.
//
// Threats: a tampered or partial snapshot must fail verification. An empty
// snapshot is not a pass. This does not execute controls and does not claim
// OS-versioned CIS coverage beyond the findings present.
func PostureEvidence(tenant, endpoint string, at time.Time, findings []core.Finding, privateKey ed25519.PrivateKey) (SignedEvidence, error) {
	if tenant == "" || endpoint == "" || at.IsZero() || len(findings) == 0 || len(findings) > 4096 {
		return SignedEvidence{}, ErrInvalidPack
	}
	results := make([]Result, 0, len(findings))
	for _, finding := range findings {
		if finding.Name == "" || finding.Category == "" || strings.ContainsAny(finding.Name, "\r\n") || strings.ContainsAny(finding.Category, "\r\n") {
			return SignedEvidence{}, ErrInvalidPack
		}
		id := finding.Category + "/" + finding.Name
		if finding.CISBenchmark != "" {
			if strings.ContainsAny(finding.CISBenchmark, "\r\n") {
				return SignedEvidence{}, ErrInvalidPack
			}
			id = "cis:" + finding.CISBenchmark + ":" + id
		}
		if len(id) > 256 {
			return SignedEvidence{}, ErrInvalidPack
		}
		raw := finding.CurrentVal
		if len(raw) > maxPostureRaw {
			raw = raw[:maxPostureRaw]
		}
		results = append(results, Result{ControlID: id, Passed: finding.Passed, Raw: raw})
	}
	return SignEvidence(EvidenceBundle{
		TenantID:    tenant,
		EndpointID:  endpoint,
		PackVersion: PostureSchemaVersion,
		CollectedAt: at.UTC(),
		Results:     results,
	}, privateKey)
}
