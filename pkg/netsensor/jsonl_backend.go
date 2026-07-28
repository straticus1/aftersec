package netsensor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const maxProviderFrameBytes = 16 * 1024

type providerEvent struct {
	Kind             string `json:"kind"`
	PID              int    `json:"pid"`
	Process          string `json:"process"`
	UID              uint32 `json:"uid"`
	LocalAddress     string `json:"localAddress"`
	LocalPort        uint16 `json:"localPort"`
	RemoteAddress    string `json:"remoteAddress"`
	RemotePort       uint16 `json:"remotePort"`
	Protocol         string `json:"protocolName"`
	BytesSent        uint64 `json:"bytesSent"`
	BytesReceived    uint64 `json:"bytesReceived"`
	Timestamp        int64  `json:"timestamp"`
	StartedTimestamp int64  `json:"startedTimestamp"`
}

type JSONLBackend struct {
	path string
}

// NewJSONLBackend accepts only a regular, non-group/world-writable event sink
// owned by root or the daemon user. Threats: an untrusted local user must not
// be able to forge process attribution into the EDR telemetry stream.
func NewJSONLBackend(path string) (*JSONLBackend, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat network event sink: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("network event sink permissions are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, fmt.Errorf("network event sink owner is untrusted")
	}
	return &JSONLBackend{path: path}, nil
}

func (b *JSONLBackend) Run(ctx context.Context, emit func(Flow) error) error {
	if b == nil || b.path == "" || emit == nil {
		return fmt.Errorf("network JSONL backend is not configured")
	}
	file, err := os.Open(b.path)
	if err != nil {
		return fmt.Errorf("open network event sink: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, maxProviderFrameBytes)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, readErr := reader.ReadBytes('\n')
		if len(frame) > maxProviderFrameBytes {
			return fmt.Errorf("network provider frame exceeds limit")
		}
		if len(frame) > 0 {
			var event providerEvent
			if err := json.Unmarshal(frame, &event); err != nil {
				return fmt.Errorf("decode network provider event: %w", err)
			}
			if event.Kind != "network_flow" || event.Timestamp <= 0 {
				return ErrInvalidFlow
			}
			at := time.Unix(event.Timestamp, 0)
			started := at
			if event.StartedTimestamp > 0 && event.StartedTimestamp <= event.Timestamp {
				started = time.Unix(event.StartedTimestamp, 0)
			}
			if err := emit(Flow{
				ProcessID:     event.PID,
				ProcessName:   event.Process,
				UserID:        event.UID,
				LocalAddress:  event.LocalAddress,
				LocalPort:     event.LocalPort,
				RemoteAddress: event.RemoteAddress,
				RemotePort:    event.RemotePort,
				Protocol:      event.Protocol,
				BytesSent:     event.BytesSent,
				BytesReceived: event.BytesReceived,
				StartedAt:     started,
				EndedAt:       at,
				Attribution:   AttributionExact,
			}); err != nil {
				return err
			}
		}
		switch readErr {
		case nil:
		case io.EOF:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		default:
			return fmt.Errorf("read network event sink: %w", readErr)
		}
	}
}
