package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScanFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		output string
		err    error
		passed bool
	}{
		{"true", nil, true}, {"false", nil, false}, {"null", nil, false}, {"", nil, false}, {"true garbage", nil, false}, {"true", errors.New("access denied"), false},
	} {
		results := scan(context.Background(), func(context.Context, string) ([]byte, error) { return []byte(tc.output), tc.err })
		if len(results) != 2 {
			t.Fatal(results)
		}
		for _, r := range results {
			if r.Passed != tc.passed {
				t.Fatalf("%+v: %+v", tc, r)
			}
		}
	}
}

func TestScanDistinguishesFailedCheckFromInvalidOutput(t *testing.T) {
	failed := scan(context.Background(), func(context.Context, string) ([]byte, error) { return []byte("false"), nil })
	invalid := scan(context.Background(), func(context.Context, string) ([]byte, error) { return []byte("null"), nil })
	if len(failed) != 2 || len(invalid) != 2 {
		t.Fatalf("failed=%+v invalid=%+v", failed, invalid)
	}
	for _, r := range failed {
		if r.Passed || r.Error != "" {
			t.Fatalf("false: %+v", r)
		}
	}
	for _, r := range invalid {
		if r.Passed || r.Error == "" {
			t.Fatalf("null: %+v", r)
		}
	}
}

func TestScanHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := scan(ctx, func(context.Context, string) ([]byte, error) { return []byte("true"), nil })
	if len(results) != 2 {
		t.Fatal(results)
	}
	for _, r := range results {
		if r.Passed || r.Error != context.Canceled.Error() {
			t.Fatal(r)
		}
	}
}

func TestScanAppliesPerCheckDeadline(t *testing.T) {
	results := scan(context.Background(), func(ctx context.Context, _ string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("missing per-check deadline")
		}
		return []byte("true"), nil
	})
	if len(results) != 2 {
		t.Fatal(results)
	}
}

func TestScanScriptsPinInboxModules(t *testing.T) {
	if !strings.Contains(powershellPreamble, "$PSModuleAutoLoadingPreference = 'None'") || !strings.Contains(powershellPreamble, "Find-SystemModule") {
		t.Fatal(powershellPreamble)
	}
	if !strings.Contains(defenderScript, "Import-Module") || !strings.Contains(defenderScript, "Defender") {
		t.Fatal(defenderScript)
	}
	if !strings.Contains(firewallScript, "NetSecurity") || !strings.Contains(firewallScript, "-Name Domain,Private,Public") {
		t.Fatal(firewallScript)
	}
	var scripts []string
	scan(context.Background(), func(_ context.Context, script string) ([]byte, error) {
		scripts = append(scripts, script)
		return []byte("true"), nil
	})
	if len(scripts) != 2 {
		t.Fatal(scripts)
	}
	for _, script := range scripts {
		if !strings.HasPrefix(script, powershellPreamble) {
			t.Fatal(script)
		}
	}
}

func TestValidateAndCleanRootRejectsSpoofedPaths(t *testing.T) {
	for _, root := range []string{"", "Windows", ".", "System32", `\\evil\share\win`, `//evil/share/win`} {
		if _, err := validateAndCleanRoot(root); err == nil {
			t.Fatalf("%q: expected rejection", root)
		}
	}
}

func TestOverrideEnvReplacesCaseInsensitiveKey(t *testing.T) {
	got := overrideEnv([]string{"PATH=/bin", "systemroot=C:\\Windows", "PSModulePath=user"}, "SystemRoot", `D:\Windows`)
	joined := strings.Join(got, ";")
	if strings.Contains(strings.ToLower(joined), "systemroot=c:\\windows") {
		t.Fatal(got)
	}
	if !strings.Contains(joined, `SystemRoot=D:\Windows`) {
		t.Fatal(got)
	}
}

func TestLimitWriterRejectsOversizedOutput(t *testing.T) {
	var w limitWriter
	if n, err := w.Write(make([]byte, maxCommandOutput)); n != maxCommandOutput || err != nil {
		t.Fatalf("exact limit: n=%d err=%v", n, err)
	}
	if _, err := w.Write([]byte{0}); err == nil {
		t.Fatal("expected overflow at 64KiB+1")
	}
	if w.data != nil {
		t.Fatal("overflow must discard partial output")
	}
	w = limitWriter{}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, maxCommandOutput)); err == nil {
		t.Fatal("expected overflow across writes")
	}
}

func TestRunPowerShellRejectsNonAbsoluteSystemRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows pins GetSystemWindowsDirectory instead of SystemRoot")
	}
	for _, root := range []string{"", "Windows", ".", "System32", `//evil/share/win`} {
		t.Setenv("SystemRoot", root)
		if _, err := runPowerShell(context.Background(), "1"); err == nil {
			t.Fatalf("SystemRoot %q: expected rejection", root)
		}
	}
}

func TestMachineModulePathStaysOnSystemDrive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows adds the Known Folder Program Files path")
	}
	root := filepath.Join(t.TempDir(), "Windows")
	got := machineModulePath(root)
	if got != filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "Modules") {
		t.Fatal(got)
	}
}

func TestPowershellExeStaysUnderRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Windows")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	command, err := powershellExe(root)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(root, command)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		t.Fatalf("escaped: %s", command)
	}
}
