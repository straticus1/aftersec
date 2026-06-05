//go:build darwin

package patchmgr

import (
	"errors"
	"testing"
)

var brewFixture = []byte(`{
  "formulae": [
    {"name":"curl","installed_versions":["8.1.0"],"current_version":"8.6.0"},
    {"name":"openssl@3","installed_versions":["3.2.0"],"current_version":"3.3.1"}
  ],
  "casks": []
}`)

func TestParseBrewJSON(t *testing.T) {
	pkgs, err := parseBrewJSON(brewFixture)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "8.1.0" || pkgs[0].LatestVersion != "8.6.0" {
		t.Errorf("unexpected pkg[0]: %+v", pkgs[0])
	}
	if pkgs[0].Source != "brew" {
		t.Errorf("expected source 'brew', got %q", pkgs[0].Source)
	}
}

func TestBrewManager_ListOutdated_ParseError(t *testing.T) {
	mgr := &BrewManager{run: func() ([]byte, error) { return []byte("not json"), nil }}
	_, err := mgr.ListOutdated()
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBrewManager_ListOutdated_RunError(t *testing.T) {
	mgr := &BrewManager{run: func() ([]byte, error) { return nil, errors.New("brew not found") }}
	_, err := mgr.ListOutdated()
	if err == nil {
		t.Error("expected error when run fails")
	}
}

func TestBrewManager_RemediateCmd(t *testing.T) {
	mgr := NewBrewManager()
	pkg := OutdatedPackage{InstalledPackage: InstalledPackage{Name: "curl"}}
	if got := mgr.RemediateCmd(pkg); got != "brew upgrade curl" {
		t.Errorf("unexpected: %q", got)
	}
}
