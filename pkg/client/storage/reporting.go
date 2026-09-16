package storage

import (
	"aftersec/pkg/eventjournal"
	"crypto/rand"
	"encoding/hex"
)

// ReportingSource exposes independent, replayable source records. No global
// enterprise acknowledgment flag is read or changed by the DarkAPI destination.
type ReportingSource interface {
	ReportingIdentity() (string, error)
	ReportingJournal(after int64, limit int) ([]eventjournal.Record, error)
	ReportingCommits(after int64, limit int) ([]map[string]any, error)
}

func (m *SQLiteManager) ReportingIdentity() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.db.Exec("CREATE TABLE IF NOT EXISTS reporting_identity(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL)"); err != nil {
		return "", err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	if _, err := m.db.Exec("INSERT OR IGNORE INTO reporting_identity(id,value) VALUES(1,?)", hex.EncodeToString(random[:])); err != nil {
		return "", err
	}
	var identity string
	err := m.db.QueryRow("SELECT value FROM reporting_identity WHERE id=1").Scan(&identity)
	return identity, err
}
func (m *SQLiteManager) ReportingJournal(after int64, limit int) ([]eventjournal.Record, error) {
	return m.eventJournal.ReadAfter(after, limit)
}
func (m *SQLiteManager) ReportingCommits(after int64, limit int) ([]map[string]any, error) {
	return m.QueryTelemetry("SELECT id,data FROM commits WHERE id>? ORDER BY id LIMIT ?", after, limit)
}
func (m *CacheManager) ReportingIdentity() (string, error) { return m.local.ReportingIdentity() }
func (m *CacheManager) ReportingJournal(after int64, limit int) ([]eventjournal.Record, error) {
	return m.local.ReportingJournal(after, limit)
}
func (m *CacheManager) ReportingCommits(after int64, limit int) ([]map[string]any, error) {
	return m.local.ReportingCommits(after, limit)
}

// Counters are scoped to this process lifetime; write failures include projection errors.
func (m *SQLiteManager) ReportingHealth() map[string]any {
	return map[string]any{"generated_attempts": m.reportAttempts.Load(), "journal_persisted": m.reportPersisted.Load(), "write_errors": m.reportFailures.Load()}
}
func (m *CacheManager) ReportingHealth() map[string]any { return m.local.ReportingHealth() }
