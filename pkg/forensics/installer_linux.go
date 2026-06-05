//go:build linux

package forensics

import (
	"context"
	"errors"
)

func AnalyzeInstaller(_ context.Context, _ string) (*PkgAnalysisResult, error) {
	return nil, errors.New("pkg installer analysis (pkgutil) is not available on Linux")
}
