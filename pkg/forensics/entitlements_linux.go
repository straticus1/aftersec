//go:build linux

package forensics

import "errors"

type EntitlementFinding struct {
	Path        string
	ThreatScore ThreatScore
	Reason      string
}

func CheckEntitlements(_ string) (EntitlementFinding, error) {
	return EntitlementFinding{}, errors.New("codesign entitlements not available on Linux")
}
