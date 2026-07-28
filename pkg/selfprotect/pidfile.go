package selfprotect

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

func WritePIDFile(path string) error {
	if !filepath.IsAbs(path) {
		return ErrUnsafeWatchdogConfig
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0o022 != 0 {
		return ErrUnsafeWatchdogConfig
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrUnsafeWatchdogConfig
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open PID file: %w", err)
	}
	if _, err := file.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		_ = file.Close()
		return fmt.Errorf("write PID file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync PID file: %w", err)
	}
	return file.Close()
}
