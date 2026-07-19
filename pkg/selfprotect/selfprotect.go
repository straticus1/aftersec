// Package selfprotect guards the agent and detects endpoint silence.
//
// Threats: unauthorized mutation and service-kill attempts are denied, while
// missing heartbeats become server-side incidents. A fully compromised kernel
// or server-side incident store remains outside the endpoint trust boundary.
package selfprotect

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnauthorizedMutation = errors.New("unauthorized agent mutation")
	ErrPathEscape           = errors.New("protected path resolution escape")
	ErrClockSkew            = errors.New("heartbeat clock skew exceeds policy")
)

type Guard struct{ protected []string }

func NewGuard(paths []string) *Guard {
	clean := make([]string, 0, len(paths))
	for _, path := range paths {
		if path = filepath.Clean(path); filepath.IsAbs(path) {
			clean = append(clean, path)
		}
	}
	return &Guard{protected: clean}
}

func (g *Guard) protects(path string) bool {
	path = filepath.Clean(path)
	for _, root := range g.protected {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (g *Guard) AuthorizeMutation(path string, signerTrusted bool) error {
	if g.protects(path) && !signerTrusted {
		return ErrUnauthorizedMutation
	}
	return nil
}

func (g *Guard) AuthorizeResolvedMutation(requested, resolved string, signerTrusted bool) error {
	if g.protects(requested) && !g.protects(resolved) {
		return ErrPathEscape
	}
	return g.AuthorizeMutation(resolved, signerTrusted)
}

type Heartbeat struct {
	TenantID   string
	HardwareID string
	At         time.Time
}

type Incident struct {
	TenantID   string
	HardwareID string
	LastSeen   time.Time
	DetectedAt time.Time
}

type IncidentStore interface{ RecordSilence(Incident) error }

type heartbeatState struct {
	heartbeat Heartbeat
	alerted   bool
}

type Tracker struct {
	mu       sync.Mutex
	deadline time.Duration
	maxSkew  time.Duration
	store    IncidentStore
	states   map[string]heartbeatState
}

func NewTracker(deadline, maxSkew time.Duration, store IncidentStore) *Tracker {
	return &Tracker{deadline: deadline, maxSkew: maxSkew, store: store, states: make(map[string]heartbeatState)}
}

func (t *Tracker) Observe(h Heartbeat, receivedAt time.Time) error {
	if h.TenantID == "" || h.HardwareID == "" || h.At.IsZero() || t.deadline <= 0 || t.maxSkew < 0 || t.store == nil {
		return errors.New("invalid heartbeat tracker input")
	}
	delta := h.At.Sub(receivedAt)
	if delta < -t.maxSkew || delta > t.maxSkew {
		return ErrClockSkew
	}
	t.mu.Lock()
	t.states[h.TenantID+"\x00"+h.HardwareID] = heartbeatState{heartbeat: h}
	t.mu.Unlock()
	return nil
}

func (t *Tracker) Check(now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, state := range t.states {
		if state.alerted || now.Sub(state.heartbeat.At) <= t.deadline {
			continue
		}
		incident := Incident{TenantID: state.heartbeat.TenantID, HardwareID: state.heartbeat.HardwareID, LastSeen: state.heartbeat.At, DetectedAt: now}
		if err := t.store.RecordSilence(incident); err != nil {
			return fmt.Errorf("record agent silence: %w", err)
		}
		state.alerted = true
		t.states[key] = state
	}
	return nil
}
