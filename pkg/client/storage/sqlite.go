package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"aftersec/pkg/core"
	"aftersec/pkg/eventjournal"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteManager struct {
	db           *sql.DB
	eventJournal *eventjournal.Journal
	baseDir      string
	mu           sync.RWMutex
}

func NewSQLiteManager(baseDir string) (*SQLiteManager, error) {
	if baseDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("get home dir: %w", err)
		}
		baseDir = filepath.Join(home, ".aftersec")
	}

	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("create base dir: %w", err)
	}

	dbPath := filepath.Join(baseDir, "aftersec.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	m := &SQLiteManager{db: db, baseDir: baseDir}
	if err := m.initSchema(); err != nil {
		return nil, err
	}
	if err := m.migrateLegacyJSON(); err != nil {
		db.Close()
		return nil, err
	}
	journal, err := eventjournal.Open(filepath.Join(baseDir, "telemetry-journal.db"), 1<<30)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("open telemetry journal: %w", err)
	}
	m.eventJournal = journal
	return m, nil
}

func (m *SQLiteManager) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS commits (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		data JSON NOT NULL
	);
	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value JSON NOT NULL
	);
	CREATE TABLE IF NOT EXISTS telemetry_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME NOT NULL,
		source TEXT NOT NULL,
		event_type TEXT NOT NULL,
		severity TEXT NOT NULL,
		details JSON NOT NULL,
		synced INTEGER DEFAULT 0,
		journal_sequence INTEGER
	);
	`
	_, err := m.db.Exec(schema)
	// Inline migration wrapper
	m.db.Exec("ALTER TABLE telemetry_events ADD COLUMN synced INTEGER DEFAULT 0")
	m.db.Exec("ALTER TABLE telemetry_events ADD COLUMN journal_sequence INTEGER")
	return err
}

func (m *SQLiteManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.eventJournal != nil {
		if err := m.eventJournal.Close(); err != nil {
			return err
		}
	}
	return m.db.Close()
}

func (m *SQLiteManager) migrateLegacyJSON() error {
	// Migrate commits
	files, err := os.ReadDir(m.baseDir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".json" && len(f.Name()) > 7 && f.Name()[:7] == "commit_" {
			path := filepath.Join(m.baseDir, f.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var st core.SecurityState
			if err := json.Unmarshal(data, &st); err == nil {
				// Insert into DB
				_, err = m.db.Exec("INSERT INTO commits (timestamp, data) VALUES (?, ?)", st.Timestamp, string(data))
				if err == nil {
					// Remove legacy file after successful migration
					os.Remove(path)
				}
			}
		}
	}
	// Migrate settings.json
	settingsPath := filepath.Join(m.baseDir, "settings.json")
	if data, err := os.ReadFile(settingsPath); err == nil {
		_, err = m.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "settings", string(data))
		if err == nil {
			os.Remove(settingsPath)
		}
	}
	return nil
}

func (m *SQLiteManager) SaveCommit(state *core.SecurityState) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	_, err = m.db.Exec("INSERT INTO commits (timestamp, data) VALUES (?, ?)", state.Timestamp, string(data))
	return err
}

func (m *SQLiteManager) GetHistory() ([]*core.SecurityState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rows, err := m.db.Query("SELECT data FROM commits ORDER BY timestamp DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []*core.SecurityState
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			continue
		}
		var st core.SecurityState
		if err := json.Unmarshal([]byte(data), &st); err == nil {
			history = append(history, &st)
		}
	}
	return history, nil
}

func (m *SQLiteManager) GetLatest() (*core.SecurityState, error) {
	history, err := m.GetHistory()
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, nil
	}
	return history[0], nil
}

func (m *SQLiteManager) GetConfigPath() string {
	return filepath.Join(m.baseDir, "aftersec.db")
}

func (m *SQLiteManager) LoadConfig() (*core.Config, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var data string
	err := m.db.QueryRow("SELECT value FROM config WHERE key = ?", "settings").Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return core.DefaultConfig(), nil
		}
		return nil, err
	}
	cfg := core.DefaultConfig()
	if err := json.Unmarshal([]byte(data), cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (m *SQLiteManager) SaveConfig(cfg *core.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = m.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", "settings", string(data))
	return err
}

func (m *SQLiteManager) LogTelemetryEvent(source, eventType, severity, details string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if details == "" {
		details = "{}"
	}
	timestamp := time.Now().UTC()
	payload, err := json.Marshal(struct {
		Timestamp string `json:"timestamp"`
		Source    string `json:"source"`
		EventType string `json:"event_type"`
		Severity  string `json:"severity"`
		Details   string `json:"details"`
	}{timestamp.Format(time.RFC3339Nano), source, eventType, severity, details})
	if err != nil {
		return fmt.Errorf("encode telemetry journal record: %w", err)
	}
	record, err := m.eventJournal.Append(payload)
	if err != nil {
		return fmt.Errorf("append telemetry journal: %w", err)
	}
	_, err = m.db.Exec("INSERT INTO telemetry_events (timestamp, source, event_type, severity, details, journal_sequence) VALUES (?, ?, ?, ?, ?, ?)",
		timestamp, source, eventType, severity, details, record.Sequence)
	return err
}

func (m *SQLiteManager) QueryTelemetry(query string, args ...any) ([]map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rows, err := m.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results []map[string]any
	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}

		rowMap := make(map[string]any)
		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			rowMap[colName] = *val
		}
		results = append(results, rowMap)
	}

	return results, nil
}

// PruneTelemetry deletes all telemetry events older than the specified number of hours
func (m *SQLiteManager) PruneTelemetry(hours int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	res, err := m.db.Exec("DELETE FROM telemetry_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetUnsyncedTelemetry fetches batches of events that have not been uploaded
func (m *SQLiteManager) GetUnsyncedTelemetry(limit int) ([]map[string]any, error) {
	return m.QueryTelemetry("SELECT id, timestamp, source, event_type, severity, details FROM telemetry_events WHERE synced = 0 ORDER BY timestamp ASC LIMIT ?", limit)
}

// MarkTelemetrySynced flags specific database rows as successfully acknowledged by the upstream server
func (m *SQLiteManager) MarkTelemetrySynced(ids []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(ids) == 0 {
		return nil
	}

	rows, err := m.db.Query("SELECT id, journal_sequence FROM telemetry_events WHERE synced = 0 ORDER BY id LIMIT ?", len(ids))
	if err != nil {
		return err
	}
	var journalSequence int64
	rowCount := 0
	for rows.Next() {
		var id int
		var sequence sql.NullInt64
		if err := rows.Scan(&id, &sequence); err != nil {
			rows.Close()
			return err
		}
		if rowCount >= len(ids) || id != ids[rowCount] || !sequence.Valid {
			rows.Close()
			return fmt.Errorf("telemetry acknowledgment is not a contiguous journal prefix")
		}
		journalSequence = sequence.Int64
		rowCount++
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if rowCount != len(ids) {
		return fmt.Errorf("telemetry acknowledgment contains missing local rows")
	}

	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec("UPDATE telemetry_events SET synced = 1 WHERE id = ? AND synced = 0", id); err != nil {
			return err
		}
	}
	if err := m.eventJournal.Acknowledge(journalSequence); err != nil {
		return fmt.Errorf("advance telemetry journal cursor: %w", err)
	}
	return tx.Commit()
}
