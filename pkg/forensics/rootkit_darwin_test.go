//go:build darwin

package forensics

import "testing"

func TestDarwinRootkitViewsRead(t *testing.T) {
	findings, err := InitRootkitDetector(nil).PerformFullScan()
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.DetectionType != "hidden_process" && finding.DetectionType != "foreign_kext" {
			t.Fatalf("unexpected finding %s", finding.DetectionType)
		}
		if finding.Severity == "" {
			t.Fatalf("finding %s has no severity", finding.DetectionType)
		}
	}
}
