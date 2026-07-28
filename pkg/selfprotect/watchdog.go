package selfprotect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var ErrUnsafeWatchdogConfig = errors.New("unsafe watchdog configuration")

type Watchdog struct {
	PIDFile   string
	AgentPath string
	Args      []string
	Interval  time.Duration
	MaxMisses int
}

// Run is intended to execute in a separately supervised watchdog process. It
// restarts the agent only from a root/current-user-owned, non-writable binary.
func (w Watchdog) Run(ctx context.Context) error {
	if err := w.validate(); err != nil {
		return err
	}
	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			alive, err := processFromPIDFileAlive(w.PIDFile)
			if err != nil {
				misses++
			} else if alive {
				misses = 0
				continue
			} else {
				misses++
			}
			if misses < w.MaxMisses {
				continue
			}
			command := exec.Command(w.AgentPath, w.Args...)
			command.SysProcAttr = watchdogProcessAttributes()
			if err := command.Start(); err != nil {
				return fmt.Errorf("restart protected agent: %w", err)
			}
			misses = 0
		}
	}
}

func (w Watchdog) validate() error {
	if !filepath.IsAbs(w.PIDFile) || !filepath.IsAbs(w.AgentPath) ||
		w.Interval <= 0 || w.MaxMisses <= 0 || len(w.Args) > 64 {
		return ErrUnsafeWatchdogConfig
	}
	info, err := os.Stat(w.AgentPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return ErrUnsafeWatchdogConfig
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return ErrUnsafeWatchdogConfig
	}
	for _, arg := range w.Args {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return ErrUnsafeWatchdogConfig
		}
	}
	return nil
}

func processFromPIDFileAlive(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return false, ErrUnsafeWatchdogConfig
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return false, ErrUnsafeWatchdogConfig
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false, err
	}
	err = process.Signal(syscall.Signal(0))
	if err == nil || errors.Is(err, os.ErrPermission) {
		return true, nil
	}
	return false, nil
}
