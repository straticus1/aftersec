//go:build darwin

package display

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type platformCapturer struct{}

func NewPlatformCapturer() Capturer { return platformCapturer{} }

// Frame runs the system screencapture tool with a fixed argument list.
// A permission denial or a missing display is an error. The shutter flag
// only mutes the camera sound; it does not bypass Screen Recording permission.
func (platformCapturer) Frame(ctx context.Context) ([]byte, error) {
	dir, err := os.MkdirTemp("", "aftersec-display-")
	if err != nil {
		return nil, fmt.Errorf("screen capture failed")
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("screen capture failed")
	}
	out := filepath.Join(dir, "frame.jpg")
	cmd := exec.CommandContext(ctx, "/usr/sbin/screencapture", "-x", "-t", "jpg", out)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdin = nil
	if err = cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("screen capture tool is unavailable")
		}
		return nil, fmt.Errorf("screen capture failed")
	}
	info, err := os.Lstat(out)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 4 || info.Size() > 16<<20 {
		return nil, fmt.Errorf("screen capture failed")
	}
	return os.ReadFile(out)
}
