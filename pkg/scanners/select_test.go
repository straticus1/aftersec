package scanners

import "testing"

func TestScanSelectionRejectsUnknownFlags(t *testing.T) {
	if err := ValidateProfile("standard"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateProfile("nope"); err == nil {
		t.Fatal("unknown profile accepted")
	}
	if !KnownCategory("filesystem") || KnownCategory("critical") {
		t.Fatal("category set")
	}
	if !MatchCategory("network", "Network Security") || MatchCategory("network", "Defaults") {
		t.Fatal("network grouping")
	}
	if !MatchCategory("all", "Defaults") {
		t.Fatal("all")
	}
}
