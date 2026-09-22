package fleetcorrelation

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecordAndPersistIsTenantScopedAndFailsClosed(t *testing.T) {
	e := NewEngine(time.Hour, 10, 2)
	sink := &MemorySink{}
	now := time.Unix(2000, 0)
	if _, err := e.RecordAndPersist(context.Background(), Event{ID: "1", TenantID: "t1", EndpointID: "a", Kind: FileHash, Value: "x", At: now}, sink); err != nil {
		t.Fatal(err)
	}
	alert, err := e.RecordAndPersist(context.Background(), Event{ID: "2", TenantID: "t1", EndpointID: "b", Kind: FileHash, Value: "x", At: now.Add(time.Minute)}, sink)
	if err != nil || alert == nil {
		t.Fatalf("alert=%+v err=%v", alert, err)
	}
	if len(sink.Alerts("t1")) != 1 || len(sink.Alerts("t2")) != 0 {
		t.Fatalf("%+v", sink.Alerts("t1"))
	}
	failing := &MemorySink{fail: errors.New("db down")}
	e2 := NewEngine(time.Hour, 10, 2)
	_, _ = e2.Record(Event{ID: "1", TenantID: "t", EndpointID: "a", Kind: SSHLogin, Value: "root", At: now})
	if _, err := e2.RecordAndPersist(context.Background(), Event{ID: "2", TenantID: "t", EndpointID: "b", Kind: SSHLogin, Value: "root", At: now}, failing); err == nil {
		t.Fatal("expected persist failure")
	}
	if _, err := e.RecordAndPersist(context.Background(), Event{ID: "3", TenantID: "t1", EndpointID: "c", Kind: FileHash, Value: "x", At: now}, nil); !errors.Is(err, ErrPersist) {
		t.Fatal(err)
	}
}
