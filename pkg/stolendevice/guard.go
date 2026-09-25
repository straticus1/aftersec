// Package stolendevice takes occasional camera frames only after an enrolled
// endpoint has been marked stolen and only while a person has unlocked it.
//
// Threats: a device that is not marked stolen, a locked session, a missing
// camera permission, or a rate limit produces no photo. The package does not
// turn off the operating-system camera indicator.
package stolendevice

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	MinDelay   = 15 * time.Second
	MaxDelay   = 90 * time.Second
	MinGap     = 3 * time.Minute
	MaxPerHour = 6
	MaxStored  = 24
)

// Guard decides whether a stolen, unlocked endpoint may take one photo.
type Guard struct {
	mu         sync.Mutex
	armed      bool
	last       time.Time
	hourStart  time.Time
	hourCount  int
	MinDelay   time.Duration
	MaxDelay   time.Duration
	MinGap     time.Duration
	MaxPerHour int
	randIntn   func(int) (int, error)
}

func NewGuard() *Guard {
	return &Guard{
		MinDelay: MinDelay, MaxDelay: MaxDelay, MinGap: MinGap, MaxPerHour: MaxPerHour,
		randIntn: cryptoIntn,
	}
}

func (g *Guard) Arm() {
	g.mu.Lock()
	g.armed = true
	g.mu.Unlock()
}

func (g *Guard) Disarm() {
	g.mu.Lock()
	g.armed = false
	g.mu.Unlock()
}

func (g *Guard) Armed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.armed
}

// Delay is how long to wait before a photo. A locked or unmarked device,
// or a device that already took its photos for this hour, is refused.
func (g *Guard) Delay(now time.Time, unlocked bool) (time.Duration, error) {
	if g == nil {
		return 0, fmt.Errorf("stolen camera is not configured")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed {
		return 0, fmt.Errorf("device is not marked stolen")
	}
	if !unlocked {
		return 0, fmt.Errorf("session is locked")
	}
	if g.MaxPerHour <= 0 || g.MinGap <= 0 {
		return 0, fmt.Errorf("stolen camera is not configured")
	}
	if g.hourStart.IsZero() || now.Sub(g.hourStart) >= time.Hour {
		g.hourStart = now
		g.hourCount = 0
	}
	if g.hourCount >= g.MaxPerHour {
		return 0, fmt.Errorf("stolen camera rate limit")
	}
	if !g.last.IsZero() && now.Sub(g.last) < g.MinGap {
		return 0, fmt.Errorf("stolen camera rate limit")
	}
	span := int((g.MaxDelay - g.MinDelay) / time.Second)
	if span <= 0 {
		return g.MinDelay, nil
	}
	n, err := g.randIntn(span)
	if err != nil {
		return 0, fmt.Errorf("stolen camera delay: %w", err)
	}
	if n < 0 || n >= span {
		return 0, fmt.Errorf("stolen camera delay was rejected")
	}
	return g.MinDelay + time.Duration(n)*time.Second, nil
}

// Mark records that a photo was taken so the next one waits.
func (g *Guard) Mark(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.last = now
	if g.hourStart.IsZero() || now.Sub(g.hourStart) >= time.Hour {
		g.hourStart = now
		g.hourCount = 0
	}
	g.hourCount++
}

func cryptoIntn(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("stolen camera delay was rejected")
	}
	var buf [2]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(buf[:])) % n, nil
}
