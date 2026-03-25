package forensics

import (
	"os/exec"
	"strings"
)

type EntitlementFinding struct {
	Path        string
	ThreatScore ThreatScore
	Reason      string
}

// CheckEntitlements dynamically extracts the XML entitlements from a signed binary 
// using codesign to look for dangerous guardrail bypass capabilities.
func CheckEntitlements(binaryPath string) (EntitlementFinding, error) {
	finding := EntitlementFinding{Path: binaryPath, ThreatScore: Safe}
	
	out, err := exec.Command("codesign", "-d", "--entitlements", ":-", binaryPath).CombinedOutput()
	if err != nil {
		outStr := string(out)
		if strings.Contains(outStr, "code object is not signed at all") {
			if strings.HasPrefix(binaryPath, "/Users/") || strings.HasPrefix(binaryPath, "/tmp/") || strings.HasPrefix(binaryPath, "/Library/") {
				finding.ThreatScore = Suspicious
				finding.Reason = "Unsigned binary executing persistently outside secure system directories"
			}
		}
		return finding, nil
	}
	
	xmlData := string(out)
	var reasons []string
	
	if strings.Contains(xmlData, "com.apple.security.cs.disable-library-validation") {
		reasons = append(reasons, "Binary allows arbitrary unsigned dylib injection (Library Validation Disabled)")
		finding.ThreatScore = Suspicious
	}
	
	if strings.Contains(xmlData, "com.apple.security.cs.allow-dyld-environment-variables") {
		reasons = append(reasons, "Binary respects dangerous DYLD_INSERT_LIBRARIES environment variables")
		finding.ThreatScore = Suspicious
	}
	
	if len(reasons) > 0 {
		finding.Reason = strings.Join(reasons, " | ")
	}
	
	return finding, nil
}
