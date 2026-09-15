package darkapi

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"aftersec/pkg/eventjournal"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalCrashGapCursorRollbackAndIndependentReplay(t *testing.T) {
	dir := t.TempDir()
	manager, err := storage.NewSQLiteManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	// Simulate a process failure after journal append but before the secondary SQL row.
	source, err := sql.Open("sqlite3", filepath.Join(dir, "aftersec.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if _, err = source.Exec("CREATE TRIGGER fail_projection BEFORE INSERT ON telemetry_events BEGIN SELECT RAISE(ABORT,'injected crash gap'); END"); err != nil {
		t.Fatal(err)
	}
	if err = manager.LogTelemetryEvent("fixture", "process.exec", "info", `{"pid":42}`); err == nil {
		t.Fatal("expected injected source projection failure")
	}
	if _, err = source.Exec("DROP TRIGGER fail_projection"); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Credentials{DeviceID: "dev_shared"})
	path := filepath.Join(t.TempDir(), "outbox.sqlite")
	exporter, err := Open(manager, c, path)
	if err != nil {
		t.Fatal(err)
	}
	exporter.maxBytes = 1
	if _, err = exporter.SyncSource(); err == nil {
		t.Fatal("expected queue capacity rejection")
	}
	if cursor, err := exporter.cursor("telemetry"); err != nil || cursor != 0 {
		t.Fatal("cursor advanced without evidence", cursor, err)
	}
	exporter.Close()
	exporter, err = Open(manager, c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	if count, err := exporter.SyncSource(); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var payload []byte
	if err = exporter.db.QueryRow("SELECT payload FROM darkapi_outbox").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var event Event
	if err = json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.Event.SchemaVersion != 2 || event.Event.Sequence != 1 || event.Event.StreamID == "" {
		t.Fatalf("missing provenance: %+v", event)
	}
	if count, err := exporter.SyncSource(); err != nil || count != 0 {
		t.Fatal("duplicate import", count, err)
	}
	if err = manager.SaveCommit(&core.SecurityState{Timestamp: time.Now(), Findings: []core.Finding{{Name: "Firewall enabled", Severity: core.High}}}); err != nil {
		t.Fatal(err)
	}
	if count, err := exporter.SyncSource(); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	records, err := manager.ReportingJournal(0, 100)
	if err != nil || len(records) != 1 {
		t.Fatal("journal mutated", err)
	}
	c.credentials.DeviceID = "dev_foreign"
	if other, err := Open(manager, c, path); err == nil {
		other.Close()
		t.Fatal("source reassigned to another device")
	}
}

func TestAlreadySyncedEnterpriseEventsStillBackfill(t *testing.T) {
	manager, err := storage.NewSQLiteManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err = manager.LogTelemetryEvent("fixture", "network.connection", "info", "{}"); err != nil {
		t.Fatal(err)
	}
	if err = manager.MarkTelemetrySynced([]int{1}); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Credentials{DeviceID: "dev_shared"})
	e, err := Open(manager, c, filepath.Join(t.TempDir(), "outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if n, err := e.SyncSource(); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	pending, err := manager.GetUnsyncedTelemetry(10)
	if err != nil || len(pending) != 0 {
		t.Fatal("enterprise acknowledgment changed", err)
	}
}

func TestPermanentPoisonIsolationAndExplicitRequeue(t *testing.T) {
	acceptBad := false
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Events []Event `json:"events"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		var ids []string
		for _, event := range body.Events {
			if event.Event.Type == "bad" && !acceptBad {
				w.WriteHeader(422)
				return
			}
			ids = append(ids, event.EventID)
		}
		w.WriteHeader(202)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "device_id": "dev_shared", "accepted_event_ids": ids})
	})
	e, err := Open(nil, c, filepath.Join(t.TempDir(), "outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	badID, _ := newID()
	for _, event := range []Event{{EventID: badID, Event: Evidence{Type: "bad"}}, {Event: Evidence{Type: "good"}}} {
		if err = e.Queue(event); err != nil {
			t.Fatal(err)
		}
	}
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, err := e.Stats()
	if err != nil || stats["accepted_total"] != int64(1) || stats["quarantined_events"] != int64(1) || stats["pending_events"] != int64(0) {
		t.Fatal(stats, err)
	}
	acceptBad = true
	if err = e.Requeue(badID); err != nil {
		t.Fatal(err)
	}
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, _ = e.Stats()
	if stats["accepted_total"] != int64(2) || stats["quarantined_events"] != int64(0) {
		t.Fatal(stats)
	}
}
func TestTransientAndAuthenticationFailuresNeverQuarantine(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(status)
			})
			e, err := Open(nil, c, filepath.Join(t.TempDir(), "outbox.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if err = e.Queue(Event{Event: Evidence{Type: "fixture"}}); err != nil {
				t.Fatal(err)
			}
			if err = e.Flush(context.Background()); err == nil {
				t.Fatal("expected failure")
			}
			stats, _ := e.Stats()
			if stats["pending_events"] != int64(1) || stats["quarantined_events"] != int64(0) {
				t.Fatal(stats)
			}
		})
	}
}
func TestRetryAfterAndBoundedBackoff(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	if parseRetryAfter("120", now) != 2*time.Minute || parseRetryAfter(now.Add(time.Minute).Format(http.TimeFormat), now) != time.Minute {
		t.Fatal("Retry-After ignored")
	}
	for i := 0; i < 20; i++ {
		delay := retryDelay(i, 2*time.Minute)
		if delay < 2*time.Minute || delay > 5*time.Minute {
			t.Fatal(delay)
		}
	}
	if parseRetryAfter("999999999", now) != time.Hour {
		t.Fatal("unbounded Retry-After")
	}
}

type malformedReportingSource struct{ storage.Manager }

func (m malformedReportingSource) ReportingIdentity() (string, error) {
	return "invalid-source-fixture", nil
}
func (m malformedReportingSource) ReportingJournal(after int64, limit int) ([]eventjournal.Record, error) {
	if after > 0 {
		return nil, nil
	}
	return []eventjournal.Record{{Sequence: 1, Payload: []byte("invalid JSON")}, {Sequence: 2, Payload: []byte(`{"timestamp":"2026-09-14T12:00:00Z","source":"fixture","event_type":"process.exec","details":"{}"}`)}}, nil
}
func (m malformedReportingSource) ReportingCommits(after int64, limit int) ([]map[string]any, error) {
	return nil, nil
}
func TestInvalidSourceQuarantineDoesNotBlockNextRecord(t *testing.T) {
	c, _ := New(Credentials{DeviceID: "dev_shared"})
	e, err := Open(malformedReportingSource{}, c, filepath.Join(t.TempDir(), "outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	n, err := e.SyncSource()
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	stats, err := e.Stats()
	if err != nil || stats["pending_events"] != int64(1) || stats["quarantined_events"] != int64(1) {
		t.Fatal(stats, err)
	}
	records, err := e.Quarantined()
	if err != nil || len(records) != 1 {
		t.Fatal(records, err)
	}
	if err = e.Requeue(records[0]["event_id"].(string)); err == nil {
		t.Fatal("invalid raw source must not be uploaded")
	}
	if cursor, err := e.cursor("telemetry"); err != nil || cursor != 2 {
		t.Fatal(cursor, err)
	}
}
