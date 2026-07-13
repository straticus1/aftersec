package eventjournal

// Threats: the journal detects deleted, reordered, or modified telemetry and
// refuses new data at its configured limit. It does not protect against an
// attacker who can replace both the database and a future external chain root.

import (
	"bytes"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestJournalPersistsAndVerifiesHashChainAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	j, err := Open(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	first, err := j.Append([]byte(`{"event":"one"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := j.Append([]byte(`{"event":"two"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Hash, second.Hash) || !bytes.Equal(second.PrevHash, first.Hash) {
		t.Fatal("records are not linked by distinct hashes")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j, err = Open(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Verify(); err != nil {
		t.Fatalf("persisted chain did not verify: %v", err)
	}
	records, err := j.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestJournalDetectsTamperedPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	j, err := Open(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE event_journal SET payload = ? WHERE sequence = 1", []byte("forged")); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if _, err := Open(path, 1<<20); !errors.Is(err, ErrTampered) {
		t.Fatalf("Open error = %v, want ErrTampered", err)
	}
}

func TestJournalFullFailsClosedWithoutDeletingEvidence(t *testing.T) {
	j, err := Open(filepath.Join(t.TempDir(), "events.db"), 5)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, err := j.Append([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append([]byte("6")); !errors.Is(err, ErrFull) {
		t.Fatalf("Append error = %v, want ErrFull", err)
	}
	records, err := j.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || string(records[0].Payload) != "12345" {
		t.Fatalf("existing evidence changed at capacity: %#v", records)
	}
}

func TestAcknowledgeAdvancesOnlyContiguousPrefix(t *testing.T) {
	j, err := Open(filepath.Join(t.TempDir(), "events.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	for _, payload := range []string{"one", "two", "three"} {
		if _, err := j.Append([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := j.Acknowledge(2); err != nil {
		t.Fatal(err)
	}
	records, err := j.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Sequence != 3 {
		t.Fatalf("pending after ack = %#v, want sequence 3 only", records)
	}
	if err := j.Acknowledge(4); !errors.Is(err, ErrInvalidAck) {
		t.Fatalf("out-of-range ack error = %v, want ErrInvalidAck", err)
	}
}
