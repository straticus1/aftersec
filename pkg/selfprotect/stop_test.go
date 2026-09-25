package selfprotect

import "testing"

func TestClassifyStopDeniesAgentUnload(t *testing.T) {
	g := NewGuard([]string{"/Library/LaunchDaemons/com.aftersec.daemon.plist"})
	err := g.ClassifyStop([]string{"launchctl", "bootout", "system/com.aftersec.daemon"})
	if err != ErrUnauthorizedStop {
		t.Fatalf("%v", err)
	}
	if err := g.ClassifyStop([]string{"launchctl", "list"}); err != nil {
		t.Fatalf("list denied: %v", err)
	}
	if err := g.ClassifyStop(nil); err != nil {
		t.Fatalf("missing argv treated as a stop: %v", err)
	}
	err = g.ClassifyStop([]string{"/bin/zsh", "-c", "launchctl bootout system/com.aftersec.daemon"})
	if err != ErrUnauthorizedStop {
		t.Fatalf("shell wrapper: %v", err)
	}
	if err := g.ClassifyStop([]string{"/bin/zsh", "-c", "echo hello"}); err != nil {
		t.Fatalf("ordinary shell denied: %v", err)
	}
}

func TestAuthorizeControllerExecFailsClosedWithoutArgs(t *testing.T) {
	g := NewGuard([]string{"/Library/LaunchDaemons/com.aftersec.daemon.plist"})
	if err := g.AuthorizeControllerExec("/bin/launchctl", nil, false); err != ErrUnauthorizedStop {
		t.Fatalf("empty argv: %v", err)
	}
	if err := g.AuthorizeControllerExec("/bin/launchctl", []string{"launchctl", "list"}, true); err != ErrUnauthorizedStop {
		t.Fatalf("truncated argv: %v", err)
	}
	if err := g.AuthorizeControllerExec("/bin/launchctl", []string{"launchctl", "list"}, false); err != nil {
		t.Fatalf("list: %v", err)
	}
	if err := g.AuthorizeControllerExec("/bin/ls", nil, true); err != nil {
		t.Fatalf("unrelated truncated exec: %v", err)
	}
	if err := (*Guard)(nil).AuthorizeControllerExec("/bin/launchctl", []string{"launchctl", "list"}, false); err != ErrInvalidStopPolicy {
		t.Fatal("nil guard")
	}
}
