// Package exposure is the cross-OS posture service.
//
// Threats: a missing tool, a timed-out probe, or an unrecognized answer is
// unknown, and unknown is not healthy. The service does not run a shell and
// does not treat a partial report as a pass.
package exposure

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"time"
)

type State string

const (
	Pass    State = "pass"
	Fail    State = "fail"
	Unknown State = "unknown"
)

type Control struct {
	ID     string `json:"id"`
	State  State  `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Platform string    `json:"platform"`
	Decision State     `json:"decision"`
	Controls []Control `json:"controls"`
}

var required = []string{"firewall", "disk_encryption", "screen_lock", "auto_update", "remote_login"}

// Decide collapses the required controls. Any fail wins. Unknown is not a pass.
func Decide(controls []Control) State {
	seen := map[string]State{}
	for _, control := range controls {
		if control.State != Pass && control.State != Fail && control.State != Unknown {
			return Unknown
		}
		seen[control.ID] = control.State
	}
	failed := false
	for _, id := range required {
		switch seen[id] {
		case Pass:
		case Fail:
			failed = true
		default:
			if !failed {
				return Unknown
			}
		}
	}
	if failed {
		return Fail
	}
	return Pass
}

type probe struct {
	output string
	ran    bool
}

// Runner executes one fixed argv. ran is false when the tool did not finish.
type Runner func(name string, args ...string) (output string, ran bool)

// Collect runs the platform probes and returns a report. An unsupported
// platform is unknown for every control.
func Collect(platform string, run Runner) Report {
	platform = normalize(platform)
	facts := map[string]probe{}
	if run != nil {
		switch platform {
		case "darwin":
			facts["firewall"] = call(run, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
			facts["disk_encryption"] = call(run, "/usr/bin/fdesetup", "status")
			facts["screen_lock"] = call(run, "/usr/bin/defaults", "read", "com.apple.screensaver", "askForPassword")
			facts["auto_update"] = call(run, "/usr/bin/defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
			facts["remote_login"] = call(run, "/usr/sbin/systemsetup", "-getremotelogin")
		case "linux":
			facts["firewall"] = call(run, "/usr/sbin/ufw", "status")
			facts["disk_encryption"] = call(run, "/usr/bin/lsblk", "-nr", "-o", "TYPE")
			facts["screen_lock"] = call(run, "/usr/bin/gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled")
			facts["auto_update"] = call(run, "/usr/bin/apt-config", "shell", "Enabled", "APT::Periodic::Enable")
			facts["remote_login"] = call(run, "/usr/bin/systemctl", "is-enabled", "ssh")
		case "windows":
			facts["firewall"] = call(run, "windows-firewall")
		}
	}
	report := Report{Platform: platform}
	for _, id := range required {
		report.Controls = append(report.Controls, Control{ID: id, State: interpret(platform, id, facts[id]), Detail: clip(facts[id].output)})
	}
	report.Decision = Decide(report.Controls)
	return report
}

func call(run Runner, name string, args ...string) probe {
	output, ran := run(name, args...)
	return probe{output: strings.TrimSpace(output), ran: ran}
}

func interpret(platform, id string, got probe) State {
	if platform != "darwin" && platform != "linux" && platform != "windows" {
		return Unknown
	}
	if !got.ran {
		return Unknown
	}
	text := got.output
	switch platform + "\x00" + id {
	case "darwin\x00firewall":
		if strings.Contains(text, "State = 1") {
			return Pass
		}
		if strings.Contains(text, "State = 0") {
			return Fail
		}
	case "darwin\x00disk_encryption":
		if strings.Contains(text, "FileVault is On.") {
			return Pass
		}
		if strings.Contains(text, "FileVault is Off.") {
			return Fail
		}
	case "darwin\x00screen_lock":
		if text == "1" {
			return Pass
		}
		if text == "0" {
			return Fail
		}
	case "darwin\x00auto_update":
		if text == "1" {
			return Pass
		}
		if text == "0" {
			return Fail
		}
	case "darwin\x00remote_login":
		if strings.Contains(text, "Remote Login: Off") {
			return Pass
		}
		if strings.Contains(text, "Remote Login: On") {
			return Fail
		}
	case "linux\x00firewall":
		if firstLine(text) == "Status: active" {
			return Pass
		}
		if firstLine(text) == "Status: inactive" {
			return Fail
		}
	case "linux\x00disk_encryption":
		if hasField(text, "crypt") {
			return Pass
		}
		if text != "" {
			return Fail
		}
	case "linux\x00screen_lock":
		if text == "true" {
			return Pass
		}
		if text == "false" {
			return Fail
		}
	case "linux\x00auto_update":
		if text == "Enabled='1'" || text == `Enabled="1"` {
			return Pass
		}
		if text == "Enabled='0'" || text == `Enabled="0"` {
			return Fail
		}
	case "linux\x00remote_login":
		if text == "disabled" || text == "masked" {
			return Pass
		}
		if text == "enabled" || text == "static" {
			return Fail
		}
	case "windows\x00firewall":
		if text == "true" {
			return Pass
		}
		if text == "false" {
			return Fail
		}
	}
	return Unknown
}

func firstLine(text string) string {
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		return strings.TrimSpace(text[:i])
	}
	return text
}

func hasField(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func normalize(platform string) string {
	switch strings.ToLower(strings.TrimSpace(platform)) {
	case "darwin", "macos":
		return "darwin"
	case "linux":
		return "linux"
	case "windows":
		return "windows"
	default:
		return ""
	}
}

func clip(text string) string {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\n", " "), "\r", " ")
	if len(text) > 160 {
		return text[:160]
	}
	return text
}

// CommandRunner is the production runner. It is not a shell.
func CommandRunner(name string, args ...string) (string, bool) {
	if name == "" || strings.Contains(name, " ") {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", false
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			return string(out), true
		}
		return "", false
	}
	return string(out), true
}

// Marshal returns the report JSON or an error. Decision is recomputed.
func Marshal(report Report) ([]byte, error) {
	report.Decision = Decide(report.Controls)
	if report.Decision != Pass && report.Decision != Fail && report.Decision != Unknown {
		return nil, errors.New("exposure decision is invalid")
	}
	return json.Marshal(report)
}
