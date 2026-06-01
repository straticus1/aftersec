//go:build linux

package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

var allowedScriptsMu sync.RWMutex

var allowedRemediationScripts = map[string]bool{}

var killCommandRegex = regexp.MustCompile(`^kill -9 \d+$`)

func RegisterAllowedScript(script string) {
	allowedScriptsMu.Lock()
	defer allowedScriptsMu.Unlock()
	allowedRemediationScripts[script] = true
}

func RunPrivileged(script string) error {
	script = strings.TrimSpace(script)

	allowedScriptsMu.RLock()
	allowed := allowedRemediationScripts[script]
	allowedScriptsMu.RUnlock()

	if !allowed && !killCommandRegex.MatchString(script) {
		h := sha256.Sum256([]byte(script))
		return fmt.Errorf("script not in allowlist (hash: %s)", hex.EncodeToString(h[:])[:16])
	}

	out, err := exec.Command("sudo", "sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("execution failed: %w (output: %s)", err, string(out))
	}
	return nil
}

func RestoreToState(targetState, currentState *SecurityState) ([]string, error) {
	var actions []string
	currentMap := make(map[string]Finding)
	for _, f := range currentState.Findings {
		currentMap[f.Name] = f
	}
	for _, targetF := range targetState.Findings {
		if !targetF.Passed || targetF.RemediationScript == "" {
			continue
		}
		currF, exists := currentMap[targetF.Name]
		if !exists {
			continue
		}
		if !currF.Passed {
			if err := RunPrivileged(currF.RemediationScript); err != nil {
				actions = append(actions, fmt.Sprintf("Failed to restore '%s': %v", targetF.Name, err))
			} else {
				actions = append(actions, fmt.Sprintf("Successfully restored '%s'", targetF.Name))
			}
		}
	}
	return actions, nil
}

func RemediateFinding(currentState *SecurityState, ruleName string) error {
	for _, f := range currentState.Findings {
		if strings.EqualFold(f.Name, ruleName) {
			if f.Passed {
				return fmt.Errorf("rule '%s' is already passed", ruleName)
			}
			if f.RemediationScript == "" {
				return fmt.Errorf("no remediation script available for '%s'", ruleName)
			}
			return RunPrivileged(f.RemediationScript)
		}
	}
	return fmt.Errorf("rule '%s' not found", ruleName)
}
