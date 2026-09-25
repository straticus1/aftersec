package oscap

import "testing"

func TestAllowsRefusesWindowsAndUnknown(t *testing.T) {
	if !Allows("darwin/arm64", "preserve") || !Allows("macOS 14", "kill_process") || !Allows("linux", "display_shot") {
		t.Fatal("unix action refused")
	}
	if Allows("windows", "kill_process") || Allows("windows/amd64", "preserve") || Allows("", "kill_process") || Allows("freebsd", "quarantine") {
		t.Fatal("unsupported platform allowed")
	}
	if Allows("darwin", "format_disk") {
		t.Fatal("unknown action allowed")
	}
}
