package preserve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMarkRejectsEscapeAndBadIncident(t *testing.T) {
	reg, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = reg.Mark("org", "HW-host", "lost", "../INCIDENT"); err == nil {
		t.Fatal("bad incident stored")
	}
	if err = reg.Mark("../org", "HW-host", "lost", "INC-10001"); err == nil {
		t.Fatal("tenant escape stored")
	}
	if err = reg.Mark("org", "HW-host", "breached", "INC-10001"); err != nil {
		t.Fatal(err)
	}
	reason, incident, ok := reg.State("org", "HW-host")
	if !ok || reason != "breached" || incident != "INC-10001" {
		t.Fatal(reason, incident, ok)
	}
	path, err := reg.file("org", "HW-host")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("lost\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok = reg.State("org", "HW-host"); ok {
		t.Fatal("truncated mark accepted")
	}
	if err = reg.Clear("org", "HW-host"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(filepath.Join(reg.root, "org", "HW-host")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
