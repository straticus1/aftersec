// Package oscap is the cross-OS action capability gate.
//
// Threats: an unknown platform or a Windows endpoint cannot receive a remote
// action. Windows has no exec, display, or preserve agent in this product, so
// the gate refuses instead of reporting success.
package oscap

import "strings"

// Allows reports whether platform can carry out a signed remote action.
// Empty and unrecognized platforms are refused.
func Allows(platform, action string) bool {
	switch family(platform) {
	case "darwin", "linux":
		switch action {
		case "kill_process", "collect_file", "read_memory", "list_persistence", "quarantine", "release_quarantine", "break_glass", "display_shot", "display_record", "mark_stolen", "clear_stolen", "preserve", "clear_preserve":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func family(platform string) string {
	s := strings.ToLower(strings.TrimSpace(platform))
	switch {
	case s == "darwin" || strings.HasPrefix(s, "darwin/") || strings.HasPrefix(s, "macos"):
		return "darwin"
	case s == "linux" || strings.HasPrefix(s, "linux/") || strings.HasPrefix(s, "linux "):
		return "linux"
	case s == "windows" || strings.HasPrefix(s, "windows"):
		return "windows"
	default:
		return ""
	}
}
