package client

import "testing"

func TestTelemetryUnixRejectsEmptyAndParsesStoredForms(t *testing.T) {
	if _, err := TelemetryUnix(""); err == nil {
		t.Fatal("empty accepted")
	}
	if _, err := TelemetryUnix(nil); err == nil {
		t.Fatal("nil accepted")
	}
	unix, err := TelemetryUnix("2026-09-25T12:00:00Z")
	if err != nil || unix <= 0 {
		t.Fatalf("%v %d", err, unix)
	}
	sqlite, err := TelemetryUnix("2026-09-25 12:00:00")
	if err != nil || sqlite != unix {
		t.Fatalf("%v %d", err, sqlite)
	}
}
