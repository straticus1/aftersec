package scanners

import (
	"aftersec/pkg/core"
	"testing"
)

func TestScanVulnerabilities_ReturnsFindings(t *testing.T) {
	var findings []core.Finding
	ScanVulnerabilities(func(f core.Finding) {
		findings = append(findings, f)
	})
	if len(findings) == 0 {
		t.Error("expected at least one finding from ScanVulnerabilities")
	}
	for _, f := range findings {
		if f.Category != "Patch Management" {
			t.Errorf("unexpected category: %q", f.Category)
		}
		if f.Name == "" {
			t.Error("finding has empty name")
		}
	}
}
