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

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteManager struct {
	db      *sql.DB
	baseDir string
	mu      sync.RWMutex
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
		return nil, err
	}
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
		synced INTEGER DEFAULT 0
	);
	`
	_, err := m.db.Exec(schema)
	// Inline migration wrapper
	m.db.Exec("ALTER TABLE telemetry_events ADD COLUMN synced INTEGER DEFAULT 0")
	return err
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
	_, err := m.db.Exec("INSERT INTO telemetry_events (timestamp, source, event_type, severity, details) VALUES (?, ?, ?, ?, ?)",
		time.Now(), source, eventType, severity, details)
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

	query := "UPDATE telemetry_events SET synced = 1 WHERE id IN ("
	args := make([]any, len(ids))
	for i, id := range ids {
		if i > 0 {
			query += ","
		}
		query += "?"
		args[i] = id
	}
	query += ")"

	_, err := m.db.Exec(query, args...)
	return err
}
