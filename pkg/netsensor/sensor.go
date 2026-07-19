// Package netsensor normalizes process-attributed network telemetry.
//
// Threats: it prevents unattributed, malformed, or silently dropped flow data
// from entering security analytics. It does not establish kernel trust; native
// backends and platform policy are responsible for attachment integrity.
package netsensor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const MaxProcessNameBytes = 256

var (
	ErrInvalidFlow        = errors.New("invalid network flow")
	ErrMissingAttribution = errors.New("missing process attribution")
	ErrQueueFull          = errors.New("network flow queue full")
)

type Attribution string

const (
	AttributionExact Attribution = "exact"
)

type Flow struct {
	ProcessID     int
	ProcessName   string
	UserID        uint32
	LocalAddress  string
	LocalPort     uint16
	RemoteAddress string
	RemotePort    uint16
	Protocol      string
	BytesSent     uint64
	BytesReceived uint64
	StartedAt     time.Time
	EndedAt       time.Time
	Attribution   Attribution
}

func (f Flow) Validate() error {
	if f.ProcessID <= 0 || strings.TrimSpace(f.ProcessName) == "" || f.Attribution != AttributionExact {
		return ErrMissingAttribution
	}
	if len(f.ProcessName) > MaxProcessNameBytes || f.LocalPort == 0 || f.RemotePort == 0 ||
		(f.Protocol != "tcp" && f.Protocol != "udp") || f.StartedAt.IsZero() ||
		f.EndedAt.Before(f.StartedAt) {
		return ErrInvalidFlow
	}
	if _, err := netip.ParseAddr(f.LocalAddress); err != nil {
		return fmt.Errorf("%w: local address", ErrInvalidFlow)
	}
	if _, err := netip.ParseAddr(f.RemoteAddress); err != nil {
		return fmt.Errorf("%w: remote address", ErrInvalidFlow)
	}
	return nil
}

type Backend interface {
	Run(context.Context, func(Flow) error) error
}

type Sensor struct {
	backend  Backend
	required bool
}

func New(backend Backend, required bool) *Sensor {
	return &Sensor{backend: backend, required: required}
}

func (s *Sensor) Run(ctx context.Context, out chan<- Flow) error {
	if s.backend == nil {
		if s.required {
			return errors.New("required network sensor backend is not configured")
		}
		return nil
	}
	err := s.backend.Run(ctx, func(flow Flow) error {
		if err := flow.Validate(); err != nil {
			return err
		}
		select {
		case out <- flow:
			return nil
		default:
			return ErrQueueFull
		}
	})
	if err != nil && s.required {
		return fmt.Errorf("required network sensor stopped: %w", err)
	}
	return err
}
