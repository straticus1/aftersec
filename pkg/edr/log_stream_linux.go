//go:build linux

package edr

import (
	"context"
	"errors"
)

type LogEvent struct {
	Timestamp     string `json:"timestamp"`
	MachTimestamp int64  `json:"machTimestamp"`
	MessageType   string `json:"messageType"`
	Category      string `json:"category"`
	Subsystem     string `json:"subsystem"`
	ProcessID     int    `json:"processID"`
	ProcessImage  string `json:"processImagePath"`
	EventMessage  string `json:"eventMessage"`
}

func StartUnifiedLogMonitor(_ context.Context, _ chan<- LogEvent) error {
	return errors.New("unified log monitoring not available on Linux")
}
