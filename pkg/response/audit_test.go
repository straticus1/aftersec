package response

import (
	"testing"
	"time"
)

func TestAuditJournalDetectsTampering(t *testing.T) {
	j := NewAuditJournal(4)
	if err := j.Append(AuditEvent{CommandID: "one", TenantID: "tenant", EndpointID: "endpoint", Action: ActionKillProcess, Status: "authorized", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(AuditEvent{CommandID: "two", TenantID: "tenant", EndpointID: "endpoint", Action: ActionCollectFile, Status: "complete", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := j.Verify(); err != nil {
		t.Fatal(err)
	}
	j.records[0].Event.Status = "altered"
	if err := j.Verify(); err == nil {
		t.Fatal("expected audit tampering detection")
	}
}

func TestAuditJournalFailsClosedAtCapacity(t *testing.T) {
	j := NewAuditJournal(1)
	e := AuditEvent{CommandID: "one", TenantID: "t", EndpointID: "e", Action: ActionKillProcess, Status: "authorized", Timestamp: time.Now()}
	if err := j.Append(e); err != nil {
		t.Fatal(err)
	}
	e.CommandID = "two"
	if err := j.Append(e); err == nil {
		t.Fatal("expected full journal rejection")
	}
}
