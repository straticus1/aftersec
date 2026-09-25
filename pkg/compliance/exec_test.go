package compliance

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCommandExecutorDoesNotUseAShell(t *testing.T) {
	runner := Runner{Executor: CommandExecutor{}, Timeout: 2 * time.Second, MaxOutputBytes: 128}
	result, err := runner.Run(context.Background(), Control{ID: "echo", Title: "echo", Command: []string{"/bin/echo", "ok"}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed || strings.TrimSpace(result.Raw) != "ok" {
		t.Fatalf("%+v", result)
	}
	executor := CommandExecutor{}
	if _, err := executor.Run(context.Background(), []string{"/bin/sh", "-c", "echo ok"}, 32); err != ErrInvalidPack {
		t.Fatalf("shell: %v", err)
	}
	if _, err := executor.Run(context.Background(), []string{"echo ok"}, 32); err != ErrInvalidPack {
		t.Fatalf("shell string: %v", err)
	}
	if _, err := executor.Run(context.Background(), nil, 32); err != ErrInvalidPack {
		t.Fatalf("empty: %v", err)
	}
}
