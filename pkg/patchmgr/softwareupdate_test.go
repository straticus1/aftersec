//go:build darwin

package patchmgr

import "testing"

var suFixture = `
Software Update found the following new or updated software:
* Label: macOS Sequoia 15.4.1-24E263
	Title: macOS Sequoia 15.4.1, Version: 15.4.1, Size: 2145360KiB, Recommended: YES,
* Label: Safari-18.4.1
	Title: Safari, Version: 18.4.1, Size: 76180KiB, Recommended: YES,
`

func TestParseSoftwareUpdateOutput(t *testing.T) {
	pkgs := parseSoftwareUpdateOutput(suFixture)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "macOS Sequoia 15.4.1-24E263" {
		t.Errorf("unexpected name: %q", pkgs[0].Name)
	}
	if pkgs[0].LatestVersion != "15.4.1" {
		t.Errorf("unexpected version: %q", pkgs[0].LatestVersion)
	}
	if pkgs[1].Name != "Safari-18.4.1" {
		t.Errorf("unexpected name: %q", pkgs[1].Name)
	}
	if pkgs[0].Source != "softwareupdate" {
		t.Errorf("expected source 'softwareupdate', got %q", pkgs[0].Source)
	}
}

func TestParseSoftwareUpdateOutput_NoUpdates(t *testing.T) {
	pkgs := parseSoftwareUpdateOutput("Software Update found no new software.")
	if len(pkgs) != 0 {
		t.Errorf("expected 0 packages, got %d", len(pkgs))
	}
}
