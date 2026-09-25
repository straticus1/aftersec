package agentinventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalCommandPassesWithoutExecuting(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".cursor/mcp.json", `{
		"mcpServers": {
			"files": {"command": "/usr/local/bin/mcp-files", "args": ["--root", "/tmp"]}
		}
	}`)
	got := Findings(home)
	if len(got) != 1 || !got[0].Passed {
		t.Fatalf("expected one passing server, got %#v", got)
	}
	if strings.Contains(got[0].LogContext, "executed") && strings.Contains(got[0].CurrentVal, "secret") {
		t.Fatal(got[0])
	}
}

func TestCleartextURLAndSecretStayFailedAndRedacted(t *testing.T) {
	home := t.TempDir()
	secret := "sk-ant-this-must-not-appear-in-the-finding"
	write(t, home, ".claude.json", `{
		"mcpServers": {
			"remote": {
				"url": "http://evil.example/mcp",
				"env": {"API_KEY": "`+secret+`"},
				"args": ["`+secret+`"]
			}
		}
	}`)
	got := Findings(home)
	if len(got) != 1 || got[0].Passed {
		t.Fatalf("expected a failed server, got %#v", got)
	}
	blob := got[0].Name + got[0].CurrentVal + got[0].LogContext + got[0].Description
	if strings.Contains(blob, secret) || strings.Contains(blob, "sk-ant-") {
		t.Fatalf("secret leaked into finding: %s", blob)
	}
	if !strings.Contains(got[0].LogContext, "cleartext") || !strings.Contains(got[0].LogContext, "API_KEY") {
		t.Fatalf("missing reasons: %s", got[0].LogContext)
	}
}

func TestOversizeMalformedAndSymlinkFailClosed(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".claude/settings.json", "{")
	big := filepath.Join(home, ".cursor", "mcp.json")
	if err := os.MkdirAll(filepath.Dir(big), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, append([]byte{'{'}, bytesOf('x', maxFileBytes+2)...), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "real.json")
	if err := os.WriteFile(target, []byte(`{"mcpServers":{"x":{"command":"npx"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".codex", "config.toml")); err != nil {
		os.MkdirAll(filepath.Join(home, ".codex"), 0o755)
		if err = os.Symlink(target, filepath.Join(home, ".codex", "config.toml")); err != nil {
			t.Fatal(err)
		}
	}
	got := Findings(home)
	var failed int
	for _, f := range got {
		if !f.Passed {
			failed++
		}
		if strings.Contains(f.LogContext+f.CurrentVal, "npx") && strings.Contains(f.Name, "codex") {
			t.Fatal("followed symlink into target config")
		}
	}
	if failed < 3 {
		t.Fatalf("expected malformed, oversize, and symlink failures, got %#v", got)
	}
}

func TestUnpinnedRunnerFails(t *testing.T) {
	home := t.TempDir()
	write(t, home, ".codex/config.toml", `
[mcp_servers.fetch]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-fetch"]
`)
	got := Findings(home)
	if len(got) != 1 || got[0].Passed || !strings.Contains(got[0].LogContext, "unpinned") {
		t.Fatalf("%#v", got)
	}
}

func TestEmptyHomeFailsClosed(t *testing.T) {
	got := Findings("  ")
	if len(got) != 1 || got[0].Passed {
		t.Fatalf("%#v", got)
	}
}

func write(t *testing.T, home, rel, body string) {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
