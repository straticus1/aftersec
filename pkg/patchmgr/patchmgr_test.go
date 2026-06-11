package patchmgr

import (
	"aftersec/pkg/core"
	"testing"
)

func TestCVESeverity(t *testing.T) {
	cases := []struct {
		scores []float64
		want   core.Severity
	}{
		{[]float64{9.8}, core.Critical},
		{[]float64{7.5}, core.High},
		{[]float64{9.8, 4.0}, core.Critical}, // highest wins
		{[]float64{5.5}, core.Med},
		{[]float64{2.0}, core.Low},
		{[]float64{}, core.Low}, // no CVEs → Low
		{[]float64{0}, core.Low},
	}
	for _, tc := range cases {
		cves := make([]CVE, len(tc.scores))
		for i, s := range tc.scores {
			cves[i] = CVE{Score: s}
		}
		got := CVESeverity(cves)
		if got != tc.want {
			t.Errorf("scores=%v: got %s, want %s", tc.scores, got, tc.want)
		}
	}
}

func TestFormatCVEs(t *testing.T) {
	cves := []CVE{
		{ID: "CVE-2024-1234", Score: 9.8},
		{ID: "CVE-2024-5678", Score: 0},
	}
	got := FormatCVEs(cves)
	if got != "CVE-2024-1234 (9.8), CVE-2024-5678" {
		t.Errorf("unexpected: %q", got)
	}
	if FormatCVEs(nil) != "" {
		t.Error("expected empty string for nil CVEs")
	}
}
