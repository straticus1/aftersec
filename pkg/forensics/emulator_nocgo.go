//go:build !cgo

package forensics

import (
	"context"
	"errors"
)

type EmulationReport struct {
	Architecture   string `json:"architecture"`
	Instructions   uint64 `json:"instructions"`
	Syscalls       int    `json:"syscalls"`
	UnpackingLoops int    `json:"unpacking_loops"`
	Score          int    `json:"score"`
	HasError       bool   `json:"has_error"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

func EmulateMachO(_ context.Context, _ string) (*EmulationReport, error) {
	return nil, errors.New("Mach-O emulation requires CGO (Unicorn engine not available in this build)")
}
