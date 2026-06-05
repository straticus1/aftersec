//go:build linux

package patchmgr

import "testing"

func TestParseAptOutput(t *testing.T) {
	fixture := `Listing...
curl/focal-security 7.68.0-1ubuntu2.22 amd64 [upgradable from: 7.68.0-1ubuntu2.21]
openssl/focal-security 1.1.1f-1ubuntu2.22 amd64 [upgradable from: 1.1.1f-1ubuntu2.21]
`
	pkgs := parseAptOutput(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "7.68.0-1ubuntu2.21" {
		t.Errorf("unexpected pkg[0]: %+v", pkgs[0])
	}
	if pkgs[0].LatestVersion != "7.68.0-1ubuntu2.22" {
		t.Errorf("unexpected latest: %q", pkgs[0].LatestVersion)
	}
}

func TestParseDnfOutput(t *testing.T) {
	fixture := `
curl.x86_64    7.76.1-31.el9    baseos
openssl.x86_64 3.0.7-28.el9     baseos
`
	pkgs := parseDnfOutput(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].LatestVersion != "7.76.1-31.el9" {
		t.Errorf("unexpected: %+v", pkgs[0])
	}
}

func TestParsePacmanOutput(t *testing.T) {
	fixture := `curl 8.1.2-1 -> 8.6.0-1
openssl 3.1.0-1 -> 3.3.1-1
`
	pkgs := parsePacmanOutput(fixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "8.1.2-1" || pkgs[0].LatestVersion != "8.6.0-1" {
		t.Errorf("unexpected: %+v", pkgs[0])
	}
}
