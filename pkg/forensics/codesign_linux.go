//go:build linux

package forensics

import (
	"context"
	"errors"
)

type SignatureInfo struct {
	Valid     bool
	Authority string
	TeamID    string
}

type AppSignatureResult struct {
	IsValid   bool
	IsAdHoc   bool
	TeamID    string
	Authority string
	Issues    []string
	RawOutput string
}

func VerifySignature(_ string) (SignatureInfo, error) {
	return SignatureInfo{}, errors.New("codesign not available on Linux")
}

func VerifyMacBundle(_ context.Context, _ string) (*AppSignatureResult, error) {
	return nil, errors.New("codesign not available on Linux")
}
