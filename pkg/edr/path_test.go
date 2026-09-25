package edr

import "testing"

func TestJoinRenameDestRejectsUnsafeNames(t *testing.T) {
	if got := JoinRenameDest("", "/tmp", "new"); got != "/tmp/new" {
		t.Fatalf("new path: %s", got)
	}
	if got := JoinRenameDest("/tmp/existing", "/tmp", "ignored"); got != "/tmp/existing" {
		t.Fatalf("existing: %s", got)
	}
	for _, name := range []string{"", ".", "..", "a/b", `a\b`} {
		if got := JoinRenameDest("", "/tmp", name); got != "" {
			t.Fatalf("%q joined to %s", name, got)
		}
	}
	if got := JoinRenameDest("", "relative", "new"); got != "" {
		t.Fatalf("relative dir: %s", got)
	}
}
