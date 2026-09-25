//go:build linux

package display

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

type platformCapturer struct{}

func NewPlatformCapturer() Capturer { return platformCapturer{} }

// Frame uses grim on a Wayland session or ImageMagick import on X11.
// Both are fixed absolute paths. A missing tool or display is an error.
func (platformCapturer) Frame(ctx context.Context) ([]byte, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if _, err := os.Stat("/usr/bin/grim"); err == nil {
			return runCapture(ctx, "/usr/bin/grim", "-t", "jpeg", "-")
		}
	}
	if os.Getenv("DISPLAY") != "" {
		if _, err := os.Stat("/usr/bin/import"); err == nil {
			return runCapture(ctx, "/usr/bin/import", "-window", "root", "jpeg:-")
		}
	}
	return nil, fmt.Errorf("screen capture tool is unavailable")
}

func runCapture(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	var stdout bytes.Buffer
	cmd.Stdout = &limitedBuffer{buf: &stdout, max: 16<<20 + 1}
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, errCaptureTooLarge) {
			return nil, fmt.Errorf("screen capture tool is unavailable")
		}
		return nil, fmt.Errorf("screen capture failed")
	}
	if stdout.Len() < 4 || stdout.Len() > 16<<20 {
		return nil, fmt.Errorf("screen capture failed")
	}
	return stdout.Bytes(), nil
}

var errCaptureTooLarge = fmt.Errorf("screen capture exceeds limit")

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.max {
		return 0, errCaptureTooLarge
	}
	return l.buf.Write(p)
}
