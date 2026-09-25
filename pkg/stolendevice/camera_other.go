//go:build !darwin && !linux

package stolendevice

import (
	"context"
	"fmt"
)

func CaptureCamera(context.Context) ([]byte, error) {
	return nil, fmt.Errorf("camera capture is not supported on this OS")
}

func SessionUnlocked(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return false, fmt.Errorf("lock state is unavailable")
}
