package fim

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvidenceCapturePairsBeforeAndAfterWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	capture := NewEvidenceCapture(1024, 4)
	if err := capture.Begin(42, path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after"), 0o600); err != nil {
		t.Fatal(err)
	}
	event, err := capture.Complete(42, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(event.Before) != "before" || string(event.After) != "after" || event.WriterPID != 42 {
		t.Fatalf("event = %+v", event)
	}
}

func TestEvidenceCaptureFailsClosedWhenBeforeEventMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if _, err := NewEvidenceCapture(1024, 4).Complete(42, path); err == nil {
		t.Fatal("expected missing evidence error")
	}
}
