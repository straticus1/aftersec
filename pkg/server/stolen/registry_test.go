package stolen

import "testing"

func TestRegistryRejectsEscapeAndRemembersClear(t *testing.T) {
	reg, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = reg.Mark("../other", "HW-host"); err == nil {
		t.Fatal("escaped tenant marked")
	}
	if err = reg.Mark("org", "HW-host"); err != nil {
		t.Fatal(err)
	}
	marked, clear := reg.State("org", "HW-host")
	if !marked || clear {
		t.Fatalf("state %v %v", marked, clear)
	}
	if err = reg.Clear("org", "HW-host"); err != nil {
		t.Fatal(err)
	}
	marked, clear = reg.State("org", "HW-host")
	if marked || !clear {
		t.Fatalf("cleared state %v %v", marked, clear)
	}
}
