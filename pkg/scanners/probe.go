package scanners

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"aftersec/pkg/core"
)

// Probe is one external check. Err is set only when the tool did not run
// (missing binary, or timeout). A non-zero exit means the tool ran and
// answered with that status; callers must not treat that as a pass.
type Probe struct {
	Output string
	Exit   int
	Err    error
}

// Ran reports whether the tool started and finished before the timeout.
func (p Probe) Ran() bool { return p.Err == nil }

// RunProbe executes name with a deadline. Combined output is trimmed and
// clipped. The process is not a shell.
func RunProbe(timeout time.Duration, name string, args ...string) Probe {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	p := Probe{Output: clipProbe(strings.TrimSpace(string(out)), 4000)}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		p.Err = fmt.Errorf("%s timed out after %s", name, timeout)
		p.Exit = -1
		return p
	}
	if err == nil {
		return p
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		p.Exit = exit.ExitCode()
		return p
	}
	p.Err = err
	p.Exit = -1
	return p
}

// probeFailed is the only legal result when a check did not get an answer.
func probeFailed(name, expected string, p Probe) core.Finding {
	why := fmt.Sprintf("exit %d", p.Exit)
	if p.Err != nil {
		why = p.Err.Error()
	}
	detail := why
	if p.Output != "" {
		detail = p.Output + " (" + why + ")"
	}
	return core.Finding{
		Category:    "Scan Engine",
		Name:        name,
		Description: "The check did not run. An unanswered probe is not a pass.",
		Severity:    core.High,
		CurrentVal:  "probe failed",
		ExpectedVal: expected,
		LogContext:  clipProbe(detail, 500),
		Passed:      false,
	}
}

func clipProbe(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
