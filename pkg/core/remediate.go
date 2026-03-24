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

var allowedRemediationScripts = map[string]bool{
	"/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on":                                                 true,
	"defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool NO":                                     true,
	"sed -i '' 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && launchctl stop com.openssh.sshd 2>/dev/null || true": true,
	"spctl --master-enable":                                                                                                true,
	"defaults write com.apple.screensaver askForPassword -int 1":                                                          true,
	"systemsetup -setremoteappleevents off":                                                                               true,
	"systemsetup -setremotelogin off":                                                                                     true,
	"defaults write com.apple.NetworkBrowser DisableAirDrop -bool YES":                                                    true,
	"defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool YES":                        true,
	"defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool YES":                                              true,
	"defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -int 0":                     true,
}

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
		scriptHash := sha256.Sum256([]byte(script))
		hashStr := hex.EncodeToString(scriptHash[:])[:16]
		return fmt.Errorf("script not in allowlist (hash: %s)", hashStr)
	}

	escapedScript := escapeForAppleScript(script)
	appleScript := fmt.Sprintf(`do shell script "%s" with administrator privileges`, escapedScript)

	cmd := exec.Command("osascript", "-e", appleScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("execution failed: %w (output: %s)", err, string(out))
	}
	return nil
}

func escapeForAppleScript(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// RestoreToState compares a target state against the current state and executes
// remediation scripts for any findings that were secure in the target state but
// are insecure in the current state.
func RestoreToState(targetState, currentState *SecurityState) ([]string, error) {
	var actions []string

	currentMap := make(map[string]Finding)
	for _, f := range currentState.Findings {
		currentMap[f.Name] = f
	}

	for _, targetF := range targetState.Findings {
		// Only restore things that were supposed to be secure
		if !targetF.Passed || targetF.RemediationScript == "" {
			continue
		}

		currF, exists := currentMap[targetF.Name]
		if !exists {
			continue
		}

		// If it was secure in the target state, but is insecure now, fix it
		if !currF.Passed {
			err := RunPrivileged(currF.RemediationScript)
			if err != nil {
				actions = append(actions, fmt.Sprintf("Failed to restore '%s': %v", targetF.Name, err))
			} else {
				actions = append(actions, fmt.Sprintf("Successfully restored '%s'", targetF.Name))
			}
		}
	}

	return actions, nil
}

// RemediateFinding executes the remediation script for a specific rule name
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
