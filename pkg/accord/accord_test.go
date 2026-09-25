package accord

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContractHoldsWhenCommandMatches(t *testing.T) {
	home, child := fixture(t, `{"mcpServers":{"files":{"command":"/usr/local/bin/mcp-files"}}}`)
	eng := NewEngine()
	eng.alive = func(int) bool { return false }
	got := eng.Observe(Exec{PID: 10, Path: child, ParentPath: "/Applications/Cursor.app/Contents/MacOS/Cursor", Home: home})
	if len(got) != 0 {
		t.Fatalf("agreement produced findings: %#v", got)
	}
}

func TestContractBreakOnUnexpectedChild(t *testing.T) {
	home, _ := fixture(t, `{"mcpServers":{"files":{"command":"/usr/local/bin/mcp-files"}}}`)
	other := filepath.Join(t.TempDir(), "npx")
	if err := os.WriteFile(other, []byte("not-the-declared-tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	eng := NewEngine()
	eng.alive = func(int) bool { return false }
	got := eng.Observe(Exec{PID: 11, Path: other, ParentPath: "/usr/local/bin/cursor", Home: home})
	if len(got) != 1 || got[0].Kind != KindContractBreak {
		t.Fatalf("%#v", got)
	}
}

func TestMalformedConfigIsRefused(t *testing.T) {
	home, child := fixture(t, `{`)
	eng := NewEngine()
	eng.alive = func(int) bool { return false }
	got := eng.Observe(Exec{PID: 12, Path: child, ParentPath: "/usr/bin/claude", Home: home})
	if len(got) != 1 || got[0].Kind != KindRefused {
		t.Fatalf("%#v", got)
	}
}

func TestIdentityDriftWhileOldPIDAlive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("version-one"), 0o700); err != nil {
		t.Fatal(err)
	}
	eng := NewEngine()
	alive := true
	eng.alive = func(int) bool { return alive }
	if got := eng.Observe(Exec{PID: 20, Path: path, ParentPath: "/bin/zsh"}); len(got) != 0 {
		t.Fatalf("first exec: %#v", got)
	}
	if err := os.WriteFile(path, []byte("version-two-replaced"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := eng.Observe(Exec{PID: 21, Path: path, ParentPath: "/bin/zsh"})
	if len(got) != 1 || got[0].Kind != KindIdentityDrift {
		t.Fatalf("%#v", got)
	}
	alive = false
	if err := os.WriteFile(path, []byte("version-three"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := eng.Observe(Exec{PID: 22, Path: path, ParentPath: "/bin/zsh"}); len(got) != 0 {
		t.Fatalf("dead pid should not drift: %#v", got)
	}
}

func TestHashFailureDoesNotClearPriorIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tool")
	if err := os.WriteFile(path, []byte("stable"), 0o700); err != nil {
		t.Fatal(err)
	}
	eng := NewEngine()
	eng.alive = func(int) bool { return true }
	if got := eng.Observe(Exec{PID: 30, Path: path}); len(got) != 0 {
		t.Fatal(got)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	got := eng.Observe(Exec{PID: 31, Path: link})
	if len(got) != 1 || got[0].Kind != KindRefused {
		t.Fatalf("%#v", got)
	}
	eng.mu.Lock()
	_, still := eng.seen[path]
	eng.mu.Unlock()
	if !still {
		t.Fatal("refused observation erased the prior hash")
	}
}

func TestLoadDriftAgainstImportBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ls")
	if err := os.WriteFile(path, []byte("plain"), 0o700); err != nil {
		t.Fatal(err)
	}
	eng := NewEngine()
	eng.alive = func(int) bool { return false }
	_ = eng.Observe(Exec{PID: 40, Path: path})
	if got := eng.ObserveMap(path, "/usr/lib/libevil.dylib"); len(got) != 1 || got[0].Kind != KindRefused {
		t.Fatalf("text file has no import baseline: %#v", got)
	}
}

func fixture(t *testing.T, config string) (home, child string) {
	t.Helper()
	home = t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cursor", "mcp.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	child = filepath.Join(t.TempDir(), "mcp-files")
	if err := os.WriteFile(child, []byte("tool"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home, child
}
