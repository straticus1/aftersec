//go:build linux || darwin

package plugins

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestYaraPropagatesErrorsAndScansEveryRule(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".aftersec", "rules")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.yar", "b.yar"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("rule"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	exe := filepath.Join(bin, "yara")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho syntax-error >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := scanYara(nil, "/tmp/target", 30*time.Second); err == nil {
		t.Fatal("swallowed scan failure")
	}
	script := "#!/bin/sh\n[ $# -eq 2 ] || exit 2\ncase \"$1\" in */b.yar) echo 'matched /tmp/target';; esac\nexit 0\n"
	if err := os.WriteFile(exe, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	malicious, err := scanYara(nil, "/tmp/target", 30*time.Second)
	if err != nil || !malicious {
		t.Fatalf("match=%v err=%v", malicious, err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho warning >&2\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if malicious, err := scanYara(nil, "/tmp/target", 30*time.Second); err != nil || malicious {
		t.Fatalf("stderr treated as match: %v %v", malicious, err)
	}
}
