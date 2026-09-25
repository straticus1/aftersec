package provenance

import "testing"

func TestObserveFailsClosed(t *testing.T) {
	if got := Observe("darwin", "/usr/bin/ls", "/usr/bin/zsh", true); got.Class != Allow {
		t.Fatal(got)
	}
	for _, tc := range []Observation{
		Observe("darwin", "/usr/local/bin/tool", "/bin/zsh", true),
		Observe("linux", "/usr/bin-evil/ls", "/bin/zsh", true),
		Observe("darwin", "/usr/bin/ls", "", true),
		Observe("darwin", "/usr/bin/ls", "/bin/zsh", false),
		Observe("windows", "/Windows/System32/cmd.exe", "explorer.exe", true),
		Observe("plan9", "/bin/ls", "/bin/sh", true),
	} {
		if tc.Class == Allow {
			t.Fatalf("allowed %+v", tc)
		}
	}
	if Observe("windows", "/usr/bin/ls", "/bin/sh", true).Class != Unsupported {
		t.Fatal("windows was not unsupported")
	}
}
