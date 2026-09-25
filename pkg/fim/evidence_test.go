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

func TestEvidenceRenameKeepsDestinationBytes(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "before")
	dest := filepath.Join(dir, "after")
	if err := os.WriteFile(from, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	event, err := NewEvidenceCapture(1024, 4).Rename(7, from, dest)
	if err != nil {
		t.Fatal(err)
	}
	if !event.Deleted || string(event.Before) != "old" || string(event.After) != "new" || event.Dest != dest {
		t.Fatalf("%+v", event)
	}
	if _, err := NewEvidenceCapture(1024, 4).Rename(7, from, "relative"); err == nil {
		t.Fatal("relative destination accepted")
	}
	missing := filepath.Join(dir, "gone")
	event, err = NewEvidenceCapture(1024, 4).Rename(7, missing, "")
	if err != nil || !event.Deleted || len(event.Before) != 0 {
		t.Fatalf("%v %+v", err, event)
	}
}

func TestEvidenceCaptureFailsClosedWhenBeforeEventMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if _, err := NewEvidenceCapture(1024, 4).Complete(42, path); err == nil {
		t.Fatal("expected missing evidence error")
	}
}
