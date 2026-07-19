package selfprotect

import (
	"errors"
	"testing"
	"time"
)

type memoryIncidentStore struct {
	incidents []Incident
	err       error
}

func (m *memoryIncidentStore) RecordSilence(i Incident) error {
	if m.err != nil {
		return m.err
	}
	m.incidents = append(m.incidents, i)
	return nil
}

func TestGuardDeniesUnsignedAgentMutation(t *testing.T) {
	g := NewGuard([]string{"/opt/aftersec/aftersecd", "/etc/aftersec/config.yaml"})
	if err := g.AuthorizeMutation("/opt/aftersec/aftersecd", false); !errors.Is(err, ErrUnauthorizedMutation) {
		t.Fatalf("AuthorizeMutation() error = %v", err)
	}
}

func TestGuardRejectsSymlinkEscape(t *testing.T) {
	g := NewGuard([]string{"/etc/aftersec"})
	if err := g.AuthorizeResolvedMutation("/etc/aftersec/config", "/tmp/config", true); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("AuthorizeResolvedMutation() error = %v", err)
	}
}

func TestTrackerRejectsClockSkewedHeartbeat(t *testing.T) {
	now := time.Unix(1000, 0)
	tr := NewTracker(time.Minute, 10*time.Second, &memoryIncidentStore{})
	if err := tr.Observe(Heartbeat{TenantID: "t1", HardwareID: "h1", At: now.Add(time.Minute)}, now); !errors.Is(err, ErrClockSkew) {
		t.Fatalf("Observe() error = %v", err)
	}
}

func TestTrackerRecordsMissingHeartbeatAsIncident(t *testing.T) {
	now := time.Unix(1000, 0)
	store := &memoryIncidentStore{}
	tr := NewTracker(time.Minute, 10*time.Second, store)
	if err := tr.Observe(Heartbeat{TenantID: "t1", HardwareID: "h1", At: now}, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Check(now.Add(time.Minute + time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(store.incidents) != 1 || store.incidents[0].HardwareID != "h1" {
		t.Fatalf("incidents = %+v", store.incidents)
	}
}

func TestTrackerFailsClosedWhenIncidentPersistenceFails(t *testing.T) {
	now := time.Unix(1000, 0)
	store := &memoryIncidentStore{err: errors.New("database unavailable")}
	tr := NewTracker(time.Minute, 10*time.Second, store)
	if err := tr.Observe(Heartbeat{TenantID: "t1", HardwareID: "h1", At: now}, now); err != nil {
		t.Fatal(err)
	}
	if err := tr.Check(now.Add(2 * time.Minute)); err == nil {
		t.Fatal("expected persistence failure to surface")
	}
}
