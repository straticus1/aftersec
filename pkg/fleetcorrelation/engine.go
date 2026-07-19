// Package fleetcorrelation detects bounded cross-endpoint attack sequences.
//
// Threats: strict tenant partitioning prevents cross-customer evidence leakage;
// duplicate, stale, and excessive events cannot silently distort detections.
// Events absent from server telemetry remain outside its visibility.
package fleetcorrelation

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrInvalidEvent = errors.New("invalid fleet event")
	ErrClockOrder   = errors.New("fleet event outside accepted clock order")
	ErrCapacity     = errors.New("fleet correlation capacity exceeded")
)

type Kind string

const (
	FileHash      Kind = "file_hash"
	SSHLogin      Kind = "ssh_login"
	CredentialUse Kind = "credential_use"
)

type Event struct {
	ID, TenantID, EndpointID string
	Kind                     Kind
	Value                    string
	At                       time.Time
}

type Alert struct {
	TenantID   string
	Kind       Kind
	Value      string
	Endpoints  []string
	DetectedAt time.Time
}

type group struct {
	last      time.Time
	endpoints map[string]time.Time
}

type Engine struct {
	mu        sync.Mutex
	window    time.Duration
	capacity  int
	threshold int
	seen      map[string]struct{}
	groups    map[string]*group
	latest    map[string]time.Time
}

func NewEngine(window time.Duration, capacity, threshold int) *Engine {
	return &Engine{window: window, capacity: capacity, threshold: threshold, seen: make(map[string]struct{}), groups: make(map[string]*group), latest: make(map[string]time.Time)}
}

func (e *Engine) Record(event Event) (*Alert, error) {
	if event.ID == "" || event.TenantID == "" || event.EndpointID == "" || event.Value == "" || event.At.IsZero() ||
		(event.Kind != FileHash && event.Kind != SSHLogin && event.Kind != CredentialUse) || e.window <= 0 || e.capacity <= 0 || e.threshold < 2 {
		return nil, ErrInvalidEvent
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	seenKey := event.TenantID + "\x00" + event.ID
	if _, duplicate := e.seen[seenKey]; duplicate {
		return nil, nil
	}
	if latest := e.latest[event.TenantID]; !latest.IsZero() && event.At.Before(latest.Add(-e.window)) {
		return nil, ErrClockOrder
	}
	key := event.TenantID + "\x00" + string(event.Kind) + "\x00" + event.Value
	g, exists := e.groups[key]
	if !exists {
		if len(e.groups) >= e.capacity {
			return nil, ErrCapacity
		}
		g = &group{endpoints: make(map[string]time.Time)}
		e.groups[key] = g
	}
	for endpoint, at := range g.endpoints {
		if event.At.Sub(at) > e.window {
			delete(g.endpoints, endpoint)
		}
	}
	g.endpoints[event.EndpointID] = event.At
	g.last = event.At
	e.seen[seenKey] = struct{}{}
	if event.At.After(e.latest[event.TenantID]) {
		e.latest[event.TenantID] = event.At
	}
	if len(g.endpoints) < e.threshold {
		return nil, nil
	}
	endpoints := make([]string, 0, len(g.endpoints))
	for endpoint := range g.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	sort.Strings(endpoints)
	return &Alert{TenantID: event.TenantID, Kind: event.Kind, Value: event.Value, Endpoints: endpoints, DetectedAt: event.At}, nil
}
