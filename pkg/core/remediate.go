package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

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

func RunPrivileged(script string) error {
	script = strings.TrimSpace(script)

	if !allowedRemediationScripts[script] && !killCommandRegex.MatchString(script) {
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
