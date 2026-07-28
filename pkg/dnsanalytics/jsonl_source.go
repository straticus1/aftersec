package dnsanalytics

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

const maxDNSProviderFrameBytes = 16 * 1024

type dnsProviderEvent struct {
	Kind      string `json:"kind"`
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Domain    string `json:"domain"`
	Protocol  string `json:"protocolName"`
	Timestamp int64  `json:"timestamp"`
}

type JSONLSource struct {
	path string
}

// NewJSONLSource accepts only an event sink which cannot be forged by an
// unprivileged local user.
func NewJSONLSource(path string) (*JSONLSource, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat DNS event sink: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("DNS event sink permissions are unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, fmt.Errorf("DNS event sink owner is untrusted")
	}
	return &JSONLSource{path: path}, nil
}

func (s *JSONLSource) Watch(ctx context.Context, emit func(Query) error) error {
	if s == nil || s.path == "" || emit == nil {
		return fmt.Errorf("DNS JSONL source is not configured")
	}
	file, err := os.Open(s.path)
	if err != nil {
		return fmt.Errorf("open DNS event sink: %w", err)
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, maxDNSProviderFrameBytes)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, readErr := reader.ReadBytes('\n')
		if len(frame) > maxDNSProviderFrameBytes {
			return fmt.Errorf("DNS provider frame exceeds limit")
		}
		if len(frame) > 0 {
			var event dnsProviderEvent
			if err := json.Unmarshal(frame, &event); err != nil {
				return fmt.Errorf("decode DNS provider event: %w", err)
			}
			if event.Kind != "dns_query" || event.Timestamp <= 0 {
				return fmt.Errorf("invalid DNS provider event")
			}
			if err := emit(Query{Domain: event.Domain, PID: event.PID, Process: event.Process, Protocol: event.Protocol}); err != nil {
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
			return fmt.Errorf("read DNS event sink: %w", readErr)
		}
	}
}
