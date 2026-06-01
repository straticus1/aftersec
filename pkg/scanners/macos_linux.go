//go:build linux

package scanners

import (
	"errors"

	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
)

type MacOSScanner struct {
	db storage.Manager
}

func NewMacOSScanner(db storage.Manager) *MacOSScanner {
	return &MacOSScanner{db: db}
}

func (s *MacOSScanner) Scan(_ func(float64, string)) (*core.SecurityState, error) {
	return nil, errors.New("macOS security scanner not available on Linux")
}
