//go:build darwin || linux

package ransomware

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

type ProcessSuspender struct{}

// Suspend issues SIGSTOP synchronously. Threats: the target may exit or PID may
// be recycled before suspension; callers must obtain PID identity from a trusted kernel event.
func (ProcessSuspender) Suspend(ctx context.Context, pid int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if pid <= 1 {
		return fmt.Errorf("refusing to suspend privileged/invalid PID")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find suspicious process: %w", err)
	}
	if err := process.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP suspicious process: %w", err)
	}
	return nil
}
