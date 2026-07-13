package storage

// Threats: enterprise telemetry must survive restart in a tamper-evident local
// queue. A modified hash-chain payload must prevent the cache from reopening.

import (
	"database/sql"
	"path/filepath"
	"testing"

	"aftersec/pkg/client"
	_ "github.com/mattn/go-sqlite3"
)

func enterpriseTestConfig(path string) *client.ClientConfig {
	return &client.ClientConfig{
		Mode:    client.ModeEnterprise,
		Storage: client.StorageConfig{Type: client.StorageCache, Path: path},
		Server:  &client.ServerConfig{Address: "127.0.0.1:9090"},
	}
}

func TestCacheManagerPersistsHashChainedTelemetryAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewCacheManager(enterpriseTestConfig(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.LogTelemetryEvent("edr", "exec", "high", `{"path":"/bin/sh"}`); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}

	mgr, err = NewCacheManager(enterpriseTestConfig(dir))
	if err != nil {
		t.Fatalf("reopen verified cache: %v", err)
	}
	defer mgr.Close()
	events, err := mgr.GetUnsyncedTelemetry(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0]["event_type"] != "exec" {
		t.Fatalf("persisted telemetry = %#v", events)
	}
}

func TestCacheManagerRejectsTamperedTelemetryJournal(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewCacheManager(enterpriseTestConfig(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.LogTelemetryEvent("edr", "exec", "high", `{"path":"/bin/sh"}`); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite3", filepath.Join(dir, "telemetry-journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE event_journal SET payload = ? WHERE sequence = 1", []byte("forged")); err != nil {
		t.Fatal(err)
	}
	db.Close()

	if mgr, err := NewCacheManager(enterpriseTestConfig(dir)); err == nil {
		mgr.Close()
		t.Fatal("enterprise cache reopened with a tampered telemetry journal")
	}
}

func TestCacheManagerRejectsAcknowledgmentWithMissingRow(t *testing.T) {
	mgr, err := NewCacheManager(enterpriseTestConfig(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()
	if err := mgr.LogTelemetryEvent("edr", "exec", "high", `{}`); err != nil {
		t.Fatal(err)
	}
	events, err := mgr.GetUnsyncedTelemetry(10)
	if err != nil {
		t.Fatal(err)
	}
	firstID := int(events[0]["id"].(int64))
	if err := mgr.MarkTelemetrySynced([]int{firstID, firstID + 1}); err == nil {
		t.Fatal("accepted acknowledgment prefix containing a nonexistent local row")
	}
}
