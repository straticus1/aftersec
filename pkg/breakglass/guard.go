// Package breakglass applies a signed, time-boxed policy override on an endpoint.
//
// Threats: unsigned, expired, replayed, stacked, or tampered overrides never
// relax enforcement. Self-protect, YARA, DarkScan, and ransomware containment
// stay on for the window. This does not replace kernel integrity if the host
// is already fully compromised.
package breakglass

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	MinDuration = time.Minute
	MaxDuration = 4 * time.Hour
)

var (
	ErrInvalidOverride = errors.New("invalid break-glass override")
	ErrAlreadyActive   = errors.New("break-glass already active")
	ErrNotActive       = errors.New("break-glass is not active")
)

type State struct {
	TenantID   string    `json:"tenant_id"`
	EndpointID string    `json:"endpoint_id"`
	Until      time.Time `json:"until"`
	AppliedAt  time.Time `json:"applied_at"`
}

type envelope struct {
	State    State  `json:"state"`
	Checksum string `json:"checksum"`
}

type Guard struct {
	mu                 sync.Mutex
	path               string
	tenant, endpointID string
	now                func() time.Time
	state              *State
}

func NewGuard(path, tenant, endpointID string, now func() time.Time) (*Guard, error) {
	if path == "" || !filepath.IsAbs(path) || endpointID == "" || now == nil {
		return nil, ErrInvalidOverride
	}
	g := &Guard{path: path, tenant: tenant, endpointID: endpointID, now: now}
	if err := g.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return g, nil
}

func ParseDuration(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d < MinDuration || d > MaxDuration {
		return 0, ErrInvalidOverride
	}
	return d, nil
}

func (g *Guard) RelaxesPolicy() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.activeLocked()
}

func (g *Guard) Status() (State, bool) {
	if g == nil {
		return State{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.activeLocked() {
		return State{}, false
	}
	return *g.state, true
}

func (g *Guard) Activate(until time.Time) error {
	if g == nil {
		return ErrInvalidOverride
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if !until.After(now) || until.After(now.Add(MaxDuration)) {
		return ErrInvalidOverride
	}
	if g.activeLocked() {
		return ErrAlreadyActive
	}
	st := State{TenantID: g.tenant, EndpointID: g.endpointID, Until: until, AppliedAt: now}
	if err := g.writeLocked(st); err != nil {
		return err
	}
	g.state = &st
	return nil
}

func (g *Guard) End() error {
	if g == nil {
		return ErrInvalidOverride
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.activeLocked() {
		return ErrNotActive
	}
	if err := os.Remove(g.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("clear break-glass state: %w", err)
	}
	g.state = nil
	return nil
}

func (g *Guard) activeLocked() bool {
	if g.state == nil {
		return false
	}
	if !g.now().Before(g.state.Until) || g.state.TenantID != g.tenant || g.state.EndpointID != g.endpointID {
		_ = os.Remove(g.path)
		g.state = nil
		return false
	}
	return true
}

func (g *Guard) load() error {
	wire, err := os.ReadFile(g.path)
	if err != nil {
		return err
	}
	if len(wire) > 1<<16 {
		return ErrInvalidOverride
	}
	var env envelope
	if json.Unmarshal(wire, &env) != nil {
		return ErrInvalidOverride
	}
	body, err := json.Marshal(env.State)
	if err != nil {
		return ErrInvalidOverride
	}
	want, err := hex.DecodeString(env.Checksum)
	if err != nil {
		return ErrInvalidOverride
	}
	got := sha256.Sum256(body)
	if len(want) != sha256.Size || subtle.ConstantTimeCompare(want, got[:]) != 1 {
		return ErrInvalidOverride
	}
	if env.State.TenantID != g.tenant || env.State.EndpointID != g.endpointID || env.State.Until.IsZero() {
		return ErrInvalidOverride
	}
	g.state = &env.State
	return nil
}

func (g *Guard) writeLocked(st State) error {
	body, err := json.Marshal(st)
	if err != nil {
		return ErrInvalidOverride
	}
	sum := sha256.Sum256(body)
	wire, err := json.Marshal(envelope{State: st, Checksum: hex.EncodeToString(sum[:])})
	if err != nil {
		return ErrInvalidOverride
	}
	if err := os.MkdirAll(filepath.Dir(g.path), 0o700); err != nil {
		return fmt.Errorf("create break-glass directory: %w", err)
	}
	tmp := g.path + ".tmp"
	if err := os.WriteFile(tmp, wire, 0o600); err != nil {
		return fmt.Errorf("write break-glass state: %w", err)
	}
	if err := os.Rename(tmp, g.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install break-glass state: %w", err)
	}
	return nil
}
