//go:build linux

package stolendevice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

// CaptureCamera uses ffmpeg's fixed v4l2 arguments. The device path is not
// taken from the caller.
func CaptureCamera(ctx context.Context) ([]byte, error) {
	if _, err := os.Stat("/usr/bin/ffmpeg"); err != nil {
		return nil, fmt.Errorf("camera capture tool is unavailable")
	}
	if _, err := os.Stat("/dev/video0"); err != nil {
		return nil, fmt.Errorf("camera capture failed")
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/ffmpeg",
		"-hide_banner", "-loglevel", "error",
		"-f", "v4l2", "-i", "/dev/video0",
		"-frames:v", "1", "-f", "image2", "-vcodec", "mjpeg", "pipe:1")
	cmd.Stdin = nil
	var stdout bytes.Buffer
	cmd.Stdout = &limitedCamera{buf: &stdout, max: 8<<20 + 1}
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, errCameraTooLarge) {
			return nil, fmt.Errorf("camera capture tool is unavailable")
		}
		return nil, fmt.Errorf("camera capture failed")
	}
	if stdout.Len() < 4 || stdout.Len() > 8<<20 {
		return nil, fmt.Errorf("camera capture failed")
	}
	return stdout.Bytes(), nil
}

var errCameraTooLarge = fmt.Errorf("camera capture exceeds limit")

type limitedCamera struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedCamera) Write(p []byte) (int, error) {
	if l.buf.Len()+len(p) > l.max {
		return 0, errCameraTooLarge
	}
	return l.buf.Write(p)
}
