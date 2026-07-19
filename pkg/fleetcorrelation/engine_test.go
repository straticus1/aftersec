package fleetcorrelation

import (
	"errors"
	"testing"
	"time"
)

func TestEngineDetectsHashFanoutWithinTenant(t *testing.T) {
	now := time.Unix(1000, 0)
	e := NewEngine(time.Hour, 100, 3)
	for i, endpoint := range []string{"a", "b", "c"} {
		alert, err := e.Record(Event{ID: string(rune('1' + i)), TenantID: "t1", EndpointID: endpoint, Kind: FileHash, Value: "sha256:bad", At: now.Add(time.Duration(i) * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		if i < 2 && alert != nil {
			t.Fatalf("early alert = %+v", alert)
		}
		if i == 2 && (alert == nil || len(alert.Endpoints) != 3) {
			t.Fatalf("alert = %+v", alert)
		}
	}
}

func TestEngineNeverCorrelatesAcrossTenants(t *testing.T) {
	e := NewEngine(time.Hour, 10, 2)
	now := time.Now()
	_, _ = e.Record(Event{ID: "1", TenantID: "t1", EndpointID: "a", Kind: FileHash, Value: "x", At: now})
	alert, err := e.Record(Event{ID: "2", TenantID: "t2", EndpointID: "b", Kind: FileHash, Value: "x", At: now})
	if err != nil || alert != nil {
		t.Fatalf("alert=%+v err=%v", alert, err)
	}
}

func TestEngineRejectsOutOfOrderBeyondClockSkew(t *testing.T) {
	e := NewEngine(time.Minute, 10, 2)
	now := time.Now()
	_, _ = e.Record(Event{ID: "1", TenantID: "t", EndpointID: "a", Kind: FileHash, Value: "x", At: now})
	_, err := e.Record(Event{ID: "2", TenantID: "t", EndpointID: "b", Kind: FileHash, Value: "x", At: now.Add(-2 * time.Minute)})
	if !errors.Is(err, ErrClockOrder) {
		t.Fatalf("Record() error = %v", err)
	}
}

func TestEngineFailsClosedAtCapacity(t *testing.T) {
	e := NewEngine(time.Hour, 1, 2)
	now := time.Now()
	_, _ = e.Record(Event{ID: "1", TenantID: "t", EndpointID: "a", Kind: FileHash, Value: "x", At: now})
	_, err := e.Record(Event{ID: "2", TenantID: "t", EndpointID: "b", Kind: FileHash, Value: "y", At: now})
	if !errors.Is(err, ErrCapacity) {
		t.Fatalf("Record() error = %v", err)
	}
}
