package dnsanalytics

import (
	"errors"
	"testing"
	"time"
)

func TestCorrelatorEmitsCompositeForDGAAndPersistenceSameProcess(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewCorrelator(5*time.Minute, 128)
	if _, err := c.RecordDNS(DNSObservation{PID: 42, Domain: "xj3k9q.example", Suspicious: true, At: now}); err != nil {
		t.Fatal(err)
	}
	detection, err := c.RecordPersistence(PersistenceObservation{PID: 42, Path: "/etc/cron.d/dropper", At: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if detection == nil || detection.PID != 42 {
		t.Fatalf("detection = %+v", detection)
	}
}

func TestCorrelatorRejectsUnattributedObservation(t *testing.T) {
	c := NewCorrelator(time.Minute, 10)
	if _, err := c.RecordDNS(DNSObservation{Domain: "bad.example", Suspicious: true, At: time.Now()}); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("RecordDNS() error = %v", err)
	}
}

func TestCorrelatorFailsClosedAtCapacity(t *testing.T) {
	now := time.Unix(1000, 0)
	c := NewCorrelator(time.Hour, 1)
	if _, err := c.RecordDNS(DNSObservation{PID: 1, Domain: "a.example", Suspicious: true, At: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RecordDNS(DNSObservation{PID: 2, Domain: "b.example", Suspicious: true, At: now}); !errors.Is(err, ErrCorrelationCapacity) {
		t.Fatalf("RecordDNS() error = %v", err)
	}
}
