package main

import (
	"aftersec/pkg/core"
	"aftersec/pkg/scanners"
)

import "C"

//export AfterSecLibVersion
func AfterSecLibVersion() *C.char {
	return C.CString("1.0.0")
}

func main() {}

// RunSecurityScan initiates a comprehensive configuration scan on the macOS system.
func RunSecurityScan() (*core.SecurityState, error) {
	scanner := scanners.NewMacOSScanner()
	return scanner.Scan(nil)
}

// CompareBaselines calculates the semantic drift between two distinct security states.
func CompareBaselines(latest, current *core.SecurityState) *core.Diff {
	return core.CompareStates(latest, current)
}

// RestoreBaseline automatically remediates regressions found in the current state versus the target.
func RestoreBaseline(target, current *core.SecurityState) ([]string, error) {
	return core.RestoreToState(target, current)
}

// RegisterAllowedScript registers a shell/Apple script string with the privileged execution engine allowing execution.
func RegisterAllowedScript(script string) {
	core.RegisterAllowedScript(script)
}

// RunPrivileged prompts via osascript to run a registered script securely as root.
func RunPrivileged(script string) error {
	return core.RunPrivileged(script)
}
