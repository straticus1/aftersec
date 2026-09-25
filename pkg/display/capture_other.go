//go:build !darwin && !linux

package display

import (
	"context"
	"fmt"
)

type platformCapturer struct{}

func NewPlatformCapturer() Capturer { return platformCapturer{} }

func (platformCapturer) Frame(context.Context) ([]byte, error) {
	return nil, fmt.Errorf("display capture is not supported on this OS")
}
