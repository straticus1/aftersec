package dnsanalytics

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidObservation  = errors.New("invalid attributed security observation")
	ErrCorrelationCapacity = errors.New("DNS correlation capacity reached")
)

type DNSObservation struct {
	PID        int
	Domain     string
	Suspicious bool
	At         time.Time
}

type PersistenceObservation struct {
	PID  int
	Path string
	At   time.Time
}

type CompositeDetection struct {
	PID             int
	Domain          string
	PersistencePath string
	DetectedAt      time.Time
}

// Correlator joins local DGA activity with persistence by attributed process.
// Threats: bounded state prevents memory exhaustion and unattributed events are
// rejected. It does not correlate activity hidden from both endpoint sensors.
type Correlator struct {
	mu       sync.Mutex
	window   time.Duration
	capacity int
	dns      map[int]DNSObservation
}

func NewCorrelator(window time.Duration, capacity int) *Correlator {
	return &Correlator{window: window, capacity: capacity, dns: make(map[int]DNSObservation)}
}

func (c *Correlator) RecordDNS(o DNSObservation) (*CompositeDetection, error) {
	if o.PID <= 0 || o.Domain == "" || o.At.IsZero() || c.window <= 0 || c.capacity <= 0 {
		return nil, ErrInvalidObservation
	}
	if !o.Suspicious {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(o.At)
	if _, exists := c.dns[o.PID]; !exists && len(c.dns) >= c.capacity {
		return nil, ErrCorrelationCapacity
	}
	c.dns[o.PID] = o
	return nil, nil
}

func (c *Correlator) RecordPersistence(o PersistenceObservation) (*CompositeDetection, error) {
	if o.PID <= 0 || o.Path == "" || o.At.IsZero() {
		return nil, ErrInvalidObservation
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expire(o.At)
	dns, ok := c.dns[o.PID]
	if !ok || o.At.Before(dns.At) || o.At.Sub(dns.At) > c.window {
		return nil, nil
	}
	delete(c.dns, o.PID)
	return &CompositeDetection{PID: o.PID, Domain: dns.Domain, PersistencePath: o.Path, DetectedAt: o.At}, nil
}

func (c *Correlator) expire(now time.Time) {
	for pid, o := range c.dns {
		if now.Sub(o.At) > c.window {
			delete(c.dns, pid)
		}
	}
}
