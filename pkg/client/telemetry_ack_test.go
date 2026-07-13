package client

// Threats: upstream acknowledgments must advance only the exact contiguous
// local telemetry prefix; oversized or malformed acknowledgments fail closed.

import "testing"

func TestAcknowledgedTelemetryIDs_ReturnsOnlyAcknowledgedPrefix(t *testing.T) {
	batch := []map[string]any{{"id": int64(10)}, {"id": int64(11)}, {"id": int64(12)}}
	ids, err := AcknowledgedTelemetryIDs(batch, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != 10 || ids[1] != 11 {
		t.Fatalf("acknowledged IDs = %v, want [10 11]", ids)
	}
}

func TestAcknowledgedTelemetryIDs_RejectsCountBeyondSentBatch(t *testing.T) {
	batch := []map[string]any{{"id": int64(10)}}
	if _, err := AcknowledgedTelemetryIDs(batch, 2); err == nil {
		t.Fatal("accepted acknowledgment count larger than sent batch")
	}
}

func TestAcknowledgedTelemetryIDs_RejectsMissingIDInPrefix(t *testing.T) {
	batch := []map[string]any{{"id": int64(10)}, {"event_type": "missing-id"}}
	if _, err := AcknowledgedTelemetryIDs(batch, 2); err == nil {
		t.Fatal("accepted acknowledged row without a durable local ID")
	}
}
