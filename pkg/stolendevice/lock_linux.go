//go:build linux

package stolendevice

import (
	"context"
	"fmt"
	"os"
)

// SessionUnlocked is true only when a graphical session is actually present.
func SessionUnlocked(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") == "" {
		return false, fmt.Errorf("lock state is unavailable")
	}
	return true, nil
}
