//go:build !darwin && !linux

package netsensor

import "fmt"

func NewPlatformBackend(_, _ string) (Backend, error) {
	return nil, fmt.Errorf("process-attributed network capture is unsupported on this platform")
}
