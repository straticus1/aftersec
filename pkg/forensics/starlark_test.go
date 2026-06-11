package forensics

import (
	"strings"
	"testing"

	"aftersec/pkg/core"
)

func TestEvaluateRules_AddFinding(t *testing.T) {
	state := &core.SecurityState{}
	script := `
add_finding(name="Test Rule", category="Custom", severity="High", desc="rule fired")
`
	if err := EvaluateRules(script, state); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(state.Findings))
	}
	f := state.Findings[0]
	if f.Name != "Test Rule" {
		t.Errorf("expected name 'Test Rule', got %q", f.Name)
	}
	if f.Category != "Custom" {
		t.Errorf("expected category 'Custom', got %q", f.Category)
	}
	if f.Severity != core.Severity("High") {
		t.Errorf("expected severity High, got %q", f.Severity)
	}
	if f.Passed {
		t.Error("findings added by rules should be marked not passed")
	}
}

func TestEvaluateRules_ReadsExistingState(t *testing.T) {
	state := &core.SecurityState{
		Findings: []core.Finding{
			{Name: "SSH Password Auth", Category: "Network", Passed: false, CurrentVal: "enabled"},
			{Name: "Firewall", Category: "Network", Passed: true, CurrentVal: "on"},
		},
	}
	// Derive a new finding only from failed controls. Starlark forbids
	// top-level for loops, so rules must wrap iteration in a function.
	script := `
def check():
    for f in state["findings"]:
        if not f["passed"]:
            add_finding(name="derived-" + f["name"], category=f["category"], severity="Medium", desc="control failed with value " + f["current_val"])

check()
`
	if err := EvaluateRules(script, state); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state.Findings) != 3 {
		t.Fatalf("expected 3 findings (2 original + 1 derived), got %d", len(state.Findings))
	}
	derived := state.Findings[2]
	if derived.Name != "derived-SSH Password Auth" {
		t.Errorf("expected derived finding from failed control, got %q", derived.Name)
	}
	if !strings.Contains(derived.Description, "enabled") {
		t.Errorf("expected current_val propagated into description, got %q", derived.Description)
	}
}

func TestEvaluateRules_ParseError(t *testing.T) {
	state := &core.SecurityState{}
	err := EvaluateRules("def broken(:\n", state)
	if err == nil {
		t.Fatal("expected error for invalid syntax")
	}
	if !strings.Contains(err.Error(), "starlark parse error") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

func TestEvaluateRules_EvalError(t *testing.T) {
	state := &core.SecurityState{}
	// Undefined names are caught at resolve time; a runtime failure like
	// division by zero is what exercises the eval-error path.
	err := EvaluateRules(`x = 1 // 0`, state)
	if err == nil {
		t.Fatal("expected error for division by zero")
	}
	if !strings.Contains(err.Error(), "starlark eval error") {
		t.Errorf("expected eval error, got: %v", err)
	}
}

func TestEvaluateRules_BadArgsToAddFinding(t *testing.T) {
	state := &core.SecurityState{}
	err := EvaluateRules(`add_finding(name="x")`, state)
	if err == nil {
		t.Fatal("expected error for missing required args")
	}
	if len(state.Findings) != 0 {
		t.Errorf("no findings should be added on error, got %d", len(state.Findings))
	}
}

func TestEvaluateRules_EmptyScript(t *testing.T) {
	state := &core.SecurityState{}
	if err := EvaluateRules("", state); err != nil {
		t.Fatalf("empty script should not error: %v", err)
	}
	if len(state.Findings) != 0 {
		t.Errorf("expected no findings, got %d", len(state.Findings))
	}
}
