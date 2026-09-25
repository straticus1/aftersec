//go:build !darwin && !linux

package attestation

import (
	"context"
	"fmt"
)

type unsupportedAttester struct{}

func NewPlatformAttester() (HardwareAttester, error) {
	return unsupportedAttester{}, nil
}

func (unsupportedAttester) Platform() string { return "" }

func (unsupportedAttester) EnsureIdentity(context.Context) (string, []byte, error) {
	return "", nil, fmt.Errorf("no hardware attestation adapter for this OS")
}

func (unsupportedAttester) Quote(context.Context, []byte) ([]byte, error) {
	return nil, fmt.Errorf("no hardware attestation adapter for this OS")
}
