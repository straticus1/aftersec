package tuning

import (
	"fmt"
	"syscall"
)

// SetProcessPriority translates an English priority string into native macOS/UNIX kernel scheduling priorities.
func SetProcessPriority(level string) error {
	var niceValue int
	switch level {
	case "background", "low", "stealth":
		niceValue = 20
	case "normal", "standard":
		niceValue = 0
	case "high", "aggressive", "performance":
		niceValue = -10
	case "realtime", "critical":
		niceValue = -20
	default:
		niceValue = 0 // Default to unprivileged zero bounds.
	}

	// PID 0 applies explicitly to the calling process.
	err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, niceValue)
	if err != nil {
		return fmt.Errorf("failed to assign nice block [%d]: %v", niceValue, err)
	}
	return nil
}
