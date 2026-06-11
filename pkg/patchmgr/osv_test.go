package patchmgr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrichWithCVEs(t *testing.T) {
	fakeResp := osvResponse{
		Results: []struct {
			Vulns []osvVuln `json:"vulns"`
		}{
			{Vulns: []osvVuln{
				{
					ID:      "GHSA-abcd-1234-efgh",
					Aliases: []string{"CVE-2024-12345"},
					Summary: "Remote code execution",
					Severity: []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					}{
						{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
					},
				},
			}},
			{Vulns: nil},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fakeResp)
	}))
	defer srv.Close()

	pkgs := []OutdatedPackage{
		{InstalledPackage: InstalledPackage{Name: "curl", Version: "8.1.0", Source: "brew"}},
		{InstalledPackage: InstalledPackage{Name: "openssl", Version: "3.2.0", Source: "brew"}},
	}

	enrichWithCVEsURL(pkgs, srv.URL)

	if len(pkgs[0].CVEs) != 1 {
		t.Fatalf("expected 1 CVE for curl, got %d", len(pkgs[0].CVEs))
	}
	if pkgs[0].CVEs[0].ID != "CVE-2024-12345" {
		t.Errorf("unexpected CVE ID: %q", pkgs[0].CVEs[0].ID)
	}
	if pkgs[0].CVEs[0].Score < 9.0 {
		t.Errorf("expected critical score, got %.1f", pkgs[0].CVEs[0].Score)
	}
	if len(pkgs[1].CVEs) != 0 {
		t.Errorf("expected 0 CVEs for openssl, got %d", len(pkgs[1].CVEs))
	}
}

func TestEnrichWithCVEs_SkipsUnknownEcosystem(t *testing.T) {
	pkgs := []OutdatedPackage{
		{InstalledPackage: InstalledPackage{Name: "something", Version: "1.0", Source: "unknown"}},
	}
	// Should not panic or make any HTTP call (no server listening)
	enrichWithCVEsURL(pkgs, "http://127.0.0.1:0")
	if len(pkgs[0].CVEs) != 0 {
		t.Errorf("expected no CVEs for unknown ecosystem")
	}
}

func TestEnrichWithCVEs_NetworkError(t *testing.T) {
	pkgs := []OutdatedPackage{
		{InstalledPackage: InstalledPackage{Name: "curl", Version: "8.1.0", Source: "brew"}},
	}
	// Bad URL — should fail silently, not panic
	enrichWithCVEsURL(pkgs, "http://127.0.0.1:1")
	if len(pkgs[0].CVEs) != 0 {
		t.Errorf("expected no CVEs on network error")
	}
}

func TestParseCVSSVector(t *testing.T) {
	cases := []struct {
		vector   string
		minScore float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.0},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 3.0},
	}
	for _, tc := range cases {
		got := parseCVSSVector(tc.vector)
		if got < tc.minScore {
			t.Errorf("vector=%q: got %.1f, want >= %.1f", tc.vector, got, tc.minScore)
		}
	}
}

func TestCVEIDFrom_PrefersAlias(t *testing.T) {
	v := osvVuln{ID: "GHSA-xxxx", Aliases: []string{"PYSEC-2024-1", "CVE-2024-9999"}}
	if got := cveIDFrom(v); got != "CVE-2024-9999" {
		t.Errorf("expected CVE alias, got %q", got)
	}
}

func TestCVEIDFrom_FallsBackToID(t *testing.T) {
	v := osvVuln{ID: "GHSA-xxxx", Aliases: []string{"PYSEC-2024-1"}}
	if got := cveIDFrom(v); got != "GHSA-xxxx" {
		t.Errorf("expected GHSA ID, got %q", got)
	}
}

func TestEcosystemFor(t *testing.T) {
	cases := map[string]string{
		"brew":   "Homebrew",
		"apt":    "Debian",
		"dnf":    "AlmaLinux",
		"pacman": "Arch Linux",
		"other":  "",
	}
	for src, want := range cases {
		if got := ecosystemFor(src); got != want {
			t.Errorf("source=%q: got %q, want %q", src, got, want)
		}
	}
}
