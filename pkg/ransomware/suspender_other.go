//go:build !darwin && !linux

package ransomware

import (
	"context"
	"fmt"
)

type ProcessSuspender struct{}

func (ProcessSuspender) Suspend(context.Context, int) error {
	return fmt.Errorf("process suspension is unsupported on this platform")
}
