// Package ransomware implements suspend-first behavioral containment.
package ransomware

import (
	"context"
	"fmt"
	"time"
)

type Policy struct {
	RenameBurst      int
	EntropyThreshold float64
}
type Event struct {
	PID         int
	Path        string
	Canary      bool
	RenameCount int
	Entropy     float64
}
type Detection struct {
	PID        int
	Path       string
	Reason     string
	DetectedAt time.Time
}
type Suspender interface {
	Suspend(context.Context, int) error
}
type Recorder interface {
	Record(context.Context, Detection) error
}
type Shield struct {
	s   Suspender
	r   Recorder
	p   Policy
	now func() time.Time
}

func NewShield(s Suspender, r Recorder, p Policy) *Shield {
	return &Shield{s: s, r: r, p: p, now: time.Now}
}

// Observe suspends a suspicious process before performing any secondary work.
// Threats: mass encryption and canary access are stopped immediately; operator disposition is out of scope.
func (s *Shield) Observe(ctx context.Context, e Event) error {
	if s.s == nil || s.r == nil || e.PID <= 0 || s.p.RenameBurst <= 0 || s.p.EntropyThreshold <= 0 {
		return fmt.Errorf("ransomware shield is not safely configured")
	}
	reason := ""
	if e.Canary {
		reason = "canary touched"
	} else if e.RenameCount >= s.p.RenameBurst && e.Entropy >= s.p.EntropyThreshold {
		reason = "encryption burst"
	} else if e.RenameCount >= s.p.RenameBurst {
		reason = "rename burst"
	}
	if reason == "" {
		return nil
	}
	if err := s.s.Suspend(ctx, e.PID); err != nil {
		return fmt.Errorf("suspend suspected ransomware: %w", err)
	}
	if err := s.r.Record(ctx, Detection{PID: e.PID, Path: e.Path, Reason: reason, DetectedAt: s.now()}); err != nil {
		return fmt.Errorf("record ransomware detection: %w", err)
	}
	return nil
}
