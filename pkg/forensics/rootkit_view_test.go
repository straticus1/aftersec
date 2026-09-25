package forensics

import "testing"

func TestConfirmedHiddenRequiresBothViewsToDisagreeTwice(t *testing.T) {
	kernel := map[int]struct{}{1: {}, 2: {}, 40: {}}
	listed := map[int]struct{}{1: {}, 2: {}}
	if got := confirmedHidden(kernel, listed, kernel, listed); len(got) != 1 || got[0] != 40 {
		t.Fatalf("hidden = %v", got)
	}
	// The pid exited before the second kernel read.
	secondKernel := map[int]struct{}{1: {}, 2: {}}
	if got := confirmedHidden(kernel, listed, secondKernel, listed); len(got) != 0 {
		t.Fatalf("exited pid reported: %v", got)
	}
	// The second process list caught up.
	secondListed := map[int]struct{}{1: {}, 2: {}, 40: {}}
	if got := confirmedHidden(kernel, listed, kernel, secondListed); len(got) != 0 {
		t.Fatalf("visible pid reported: %v", got)
	}
}

func TestParsePIDLinesRejectsACorruptView(t *testing.T) {
	pids, err := parsePIDLines("1\n2\n\n10\n")
	if err != nil || len(pids) != 3 {
		t.Fatal(err, pids)
	}
	if _, err = parsePIDLines("1\nnot-a-pid\n"); err == nil {
		t.Fatal("corrupt process list accepted")
	}
	if _, err = parsePIDLines("\n"); err == nil {
		t.Fatal("empty process list accepted")
	}
}

func TestNonAppleKextsIgnoreAppleBundles(t *testing.T) {
	text := "Index Refs Address Size Wired Name (Version) UUID\n" +
		"1 0 0xffffff7f80c3e000 0x1000 0x1000 com.apple.kpi.bsd (20.0.0) <>\n" +
		"2 1 0xffffff7f80c4e000 0x2000 0x2000 com.example.hidden (1) <>\n"
	names, err := nonAppleKexts(text)
	if err != nil || len(names) != 1 || names[0] != "com.example.hidden" {
		t.Fatal(err, names)
	}
	if _, err = nonAppleKexts("1 0 0 0 0 com.example.hidden\n"); err == nil {
		t.Fatal("kext view without a header accepted")
	}
	if _, err = nonAppleKexts(""); err == nil {
		t.Fatal("empty kext view accepted")
	}
}

func TestModuleReviewIsCrossViewOrKnownName(t *testing.T) {
	if moduleNeedsReview(false, true) {
		t.Fatal("ordinary in-sysfs module flagged")
	}
	if !moduleNeedsReview(false, false) {
		t.Fatal("module missing from sysfs was cleared")
	}
	if !moduleNeedsReview(true, true) {
		t.Fatal("known name in sysfs was cleared")
	}
}

func TestSuspiciousLibraryPath(t *testing.T) {
	if suspiciousLibraryPath("/usr/lib/libexample.so") {
		t.Fatal("system library flagged")
	}
	for _, path := range []string{"", "libevil.so", "/tmp/libevil.so", "/usr/lib/../tmp/lib.so", "/opt/libevil.so"} {
		if !suspiciousLibraryPath(path) {
			t.Fatalf("accepted %q", path)
		}
	}
}
