package plugins

import (
	"os"
	"path/filepath"
	"testing"

	"aftersec/pkg/core"
)

// writeScript drops a script into the scripts dir under the test HOME.
func writeScript(t *testing.T, name, content string) {
	t.Helper()
	dir := filepath.Join(os.Getenv("HOME"), ".aftersec", "scripts")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func collectFindings(t *testing.T) []core.Finding {
	t.Helper()
	var findings []core.Finding
	ScanStarlark(nil, func(f core.Finding) {
		findings = append(findings, f)
	})
	return findings
}

func TestScanStarlark_NoScriptsDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if got := collectFindings(t); len(got) != 0 {
		t.Errorf("expected no findings without scripts dir, got %d", len(got))
	}
}

func TestScanStarlark_ReportFinding(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeScript(t, "check.star", `
report_finding(category="Hardening", name="Test Check", desc="a custom check", severity="High", current_val="off", expected_val="on", passed=False, remediation_script="echo fix")
`)
	findings := collectFindings(t)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Name != "Custom Rule: Test Check" {
		t.Errorf("expected prefixed name, got %q", f.Name)
	}
	if f.Category != "Hardening" || f.CurrentVal != "off" || f.ExpectedVal != "on" {
		t.Errorf("finding fields not propagated: %+v", f)
	}
	if f.Passed {
		t.Error("expected passed=false")
	}
	if f.RemediationScript != "echo fix" {
		t.Errorf("expected remediation script propagated, got %q", f.RemediationScript)
	}
	if f.LogContext != "Starlark Script: check.star" {
		t.Errorf("expected script name in log context, got %q", f.LogContext)
	}
}

func TestScanStarlark_IgnoresNonStarFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeScript(t, "notes.txt", `this is not starlark`)
	writeScript(t, "check.py", `report_finding()`)
	if got := collectFindings(t); len(got) != 0 {
		t.Errorf("expected non-.star files to be ignored, got %d findings", len(got))
	}
}

func TestScanStarlark_RunCommandRejectsUnlistedCommand(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// The script errors at run_command, so the finding before it survives
	// and the one after is never reported.
	writeScript(t, "bad.star", `
report_finding(category="A", name="before", desc="d", severity="Low", current_val="", expected_val="", passed=True)
run_command(cmd="rm")
report_finding(category="A", name="after", desc="d", severity="Low", current_val="", expected_val="", passed=True)
`)
	findings := collectFindings(t)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (script halts at disallowed command), got %d", len(findings))
	}
	if findings[0].Name != "Custom Rule: before" {
		t.Errorf("expected the pre-error finding, got %q", findings[0].Name)
	}
}

func TestScanStarlark_RunCommandRejectsShellMetacharacters(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	writeScript(t, "inject.star", `
run_command(cmd="defaults_read", args=["com.apple.dock; rm -rf /"])
report_finding(category="A", name="after", desc="d", severity="Low", current_val="", expected_val="", passed=True)
`)
	if got := collectFindings(t); len(got) != 0 {
		t.Errorf("expected script to halt on metacharacter rejection, got %d findings", len(got))
	}
}

func TestScanStarlark_ErrorInOneScriptDoesNotStopOthers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	// Scripts run in directory order: a_bad.star errors, b_good.star still runs.
	writeScript(t, "a_bad.star", `undefined_function()`)
	writeScript(t, "b_good.star", `
report_finding(category="A", name="good", desc="d", severity="Low", current_val="", expected_val="", passed=True)
`)
	findings := collectFindings(t)
	if len(findings) != 1 {
		t.Fatalf("expected the good script to still run, got %d findings", len(findings))
	}
	if findings[0].Name != "Custom Rule: good" {
		t.Errorf("unexpected finding: %q", findings[0].Name)
	}
}

func TestNumStarlarkRules(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if n := NumStarlarkRules(); n != 0 {
		t.Errorf("expected 0 rules in empty home, got %d", n)
	}
	writeScript(t, "one.star", ``)
	writeScript(t, "two.star", ``)
	writeScript(t, "ignored.txt", ``)
	if n := NumStarlarkRules(); n != 2 {
		t.Errorf("expected 2 rules, got %d", n)
	}
}
