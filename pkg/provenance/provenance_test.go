package provenance

import (
	"os"
	"testing"
)

func TestObserveFailsClosed(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if got := Observe("darwin", "/usr/bin/ls", "/usr/bin/zsh", hash, true); got.Class != Allow || got.SHA256 != hash {
		t.Fatal(got)
	}
	for _, tc := range []Observation{
		Observe("darwin", "/usr/bin/ls", "/usr/bin/zsh", "", true),
		Observe("darwin", "/usr/bin/ls", "/usr/bin/zsh", "ABCD", true),
		Observe("darwin", "/usr/local/bin/tool", "/bin/zsh", hash, true),
		Observe("linux", "/usr/bin-evil/ls", "/bin/zsh", hash, true),
		Observe("darwin", "/usr/bin/ls", "", hash, true),
		Observe("darwin", "/usr/bin/ls", "/bin/zsh", hash, false),
		Observe("windows", "/Windows/System32/cmd.exe", "explorer.exe", hash, true),
		Observe("plan9", "/bin/ls", "/bin/sh", hash, true),
	} {
		if tc.Class == Allow {
			t.Fatalf("allowed %+v", tc)
		}
	}
	if Observe("windows", "/usr/bin/ls", "/bin/sh", hash, true).Class != Unsupported {
		t.Fatal("windows was not unsupported")
	}
}

func TestInspectRejectsWritableAndSymlink(t *testing.T) {
	dir := t.TempDir()
	bin := dir + "/tool"
	if err := os.WriteFile(bin, []byte("aftersec"), 0o755); err != nil {
		t.Fatal(err)
	}
	hash, sealed := Inspect(bin)
	if !sealed || hash == "" {
		t.Fatal(hash, sealed)
	}
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, sealed = Inspect(bin); sealed {
		t.Fatal("writable file sealed")
	}
	link := dir + "/link"
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	if _, sealed = Inspect(link); sealed {
		t.Fatal("symlink sealed")
	}
}
