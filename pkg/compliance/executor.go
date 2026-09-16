package compliance

import (
	"context"
	"os/exec"
	"sync"
)

// CommandExecutor executes the signed control's argv directly, without a shell.
// Control exit status zero means compliant; nonzero means noncompliant.
type CommandExecutor struct{}

func (CommandExecutor) Run(ctx context.Context, args []string, limit int) ([]byte, error) {
	if len(args) == 0 || args[0] == "" || limit <= 0 {
		return nil, ErrInvalidPack
	}
	output := &boundedOutput{limit: limit}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if output.exceeded {
		return nil, ErrOutputTooLarge
	}
	return output.data, err
}

type boundedOutput struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	exceeded bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > b.limit-len(b.data) {
		b.exceeded = true
		return 0, ErrOutputTooLarge
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
