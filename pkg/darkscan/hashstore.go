package darkscan

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// HashStore wraps SQLite database for scan deduplication and history
type HashStore struct {
	db      *sql.DB
	enabled bool
}

// HashEntry represents a stored hash with scan history
type HashEntry struct {
	Hash        string
	FirstSeen   time.Time
	LastSeen    time.Time
	ScanCount   int
	Infected    bool
	ThreatLevel ThreatLevel
	Threats     []Threat
	FilePath    string
}

// HistoryFilter filters scan history queries
type HistoryFilter struct {
	StartTime   *time.Time
	EndTime     *time.Time
	Infected    *bool
	ThreatLevel *ThreatLevel
	Limit       int
	Offset      int
}

// NewHashStore creates a new hash store instance
func NewHashStore(cfg *Config) (*HashStore, error) {
	if !cfg.HashStore.Enabled {
		return &HashStore{enabled: false}, nil
	}

	// Ensure database directory exists
	dbPath := cfg.HashStore.DatabasePath
	if dbPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dbPath = filepath.Join(homeDir, ".aftersec", "darkscan", "hashes.db")
	}

	// Expand tilde in path
	if len(dbPath) > 0 && dbPath[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dbPath = filepath.Join(homeDir, dbPath[1:])
	}

	// Create parent directory
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open SQLite database
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Create table if it doesn't exist
	schema := `
	CREATE TABLE IF NOT EXISTS hash_store (
		hash TEXT PRIMARY KEY,
		file_path TEXT,
		first_seen TIMESTAMP,
		last_seen TIMESTAMP,
		scan_count INTEGER,
		infected BOOLEAN,
		threat_level INTEGER,
		threats TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_last_seen ON hash_store(last_seen);
	CREATE INDEX IF NOT EXISTS idx_infected ON hash_store(infected);
	`

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &HashStore{
		db:      db,
		enabled: true,
	}, nil
}

// CalculateFileHash computes SHA256 hash of a file
func CalculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CheckHash queries the hash store for a file hash
func (h *HashStore) CheckHash(ctx context.Context, hash string) (*HashEntry, error) {
	if !h.enabled {
		return nil, fmt.Errorf("hash store not enabled")
	}

	query := `
		SELECT hash, file_path, first_seen, last_seen, scan_count, infected, threat_level, threats
		FROM hash_store
		WHERE hash = ?
	`

	var entry HashEntry
	var threatsJSON string
	var threatLevel int

	err := h.db.QueryRowContext(ctx, query, hash).Scan(
		&entry.Hash,
		&entry.FilePath,
		&entry.FirstSeen,
		&entry.LastSeen,
		&entry.ScanCount,
		&entry.Infected,
		&threatLevel,
		&threatsJSON,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query hash: %w", err)
	}

	entry.ThreatLevel = ThreatLevel(threatLevel)
	if threatsJSON != "" {
		if err := json.Unmarshal([]byte(threatsJSON), &entry.Threats); err != nil {
			entry.Threats = []Threat{}
		}
	}

	return &entry, nil
}

// StoreResult stores a scan result in the hash store
func (h *HashStore) StoreResult(ctx context.Context, result *ScanResult) error {
	if !h.enabled {
		return nil // Silently skip if disabled
	}

	// Calculate file hash
	hash, err := CalculateFileHash(result.FilePath)
	if err != nil {
		return fmt.Errorf("failed to calculate hash: %w", err)
	}

	now := time.Now()
	threatLevel := CalculateThreatLevel(result)

	// Marshal threats to JSON
	threatsJSON, err := json.Marshal(result.Threats)
	if err != nil {
		threatsJSON = []byte("[]")
	}

	// Use UPSERT to insert or update
	query := `
		INSERT INTO hash_store (hash, file_path, first_seen, last_seen, scan_count, infected, threat_level, threats)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?)
		ON CONFLICT(hash) DO UPDATE SET
			file_path = excluded.file_path,
			last_seen = excluded.last_seen,
			scan_count = scan_count + 1,
			infected = excluded.infected,
			threat_level = excluded.threat_level,
			threats = excluded.threats
	`

	_, err = h.db.ExecContext(ctx, query,
		hash,
		result.FilePath,
		now,
		now,
		result.Infected,
		int(threatLevel),
		string(threatsJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to store hash entry: %w", err)
	}

	return nil
}

// GetScanHistory retrieves scan history with optional filters
func (h *HashStore) GetScanHistory(ctx context.Context, filters HistoryFilter) ([]*HashEntry, error) {
	if !h.enabled {
		return nil, fmt.Errorf("hash store not enabled")
	}

	query := `
		SELECT hash, file_path, first_seen, last_seen, scan_count, infected, threat_level, threats
		FROM hash_store
		WHERE 1=1
	`
	args := []interface{}{}

	if filters.StartTime != nil {
		query += " AND last_seen >= ?"
		args = append(args, *filters.StartTime)
	}
	if filters.EndTime != nil {
		query += " AND last_seen <= ?"
		args = append(args, *filters.EndTime)
	}
	if filters.Infected != nil {
		query += " AND infected = ?"
		args = append(args, *filters.Infected)
	}
	if filters.ThreatLevel != nil {
		query += " AND threat_level >= ?"
		args = append(args, int(*filters.ThreatLevel))
	}

	query += " ORDER BY last_seen DESC"

	limit := filters.Limit
	if limit <= 0 {
		limit = 100
	}
	query += " LIMIT ?"
	args = append(args, limit)

	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}

	rows, err := h.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query history: %w", err)
	}
	defer rows.Close()

	var result []*HashEntry
	for rows.Next() {
		var entry HashEntry
		var threatsJSON string
		var threatLevel int

		err := rows.Scan(
			&entry.Hash,
			&entry.FilePath,
			&entry.FirstSeen,
			&entry.LastSeen,
			&entry.ScanCount,
			&entry.Infected,
			&threatLevel,
			&threatsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		entry.ThreatLevel = ThreatLevel(threatLevel)
		if threatsJSON != "" {
			if err := json.Unmarshal([]byte(threatsJSON), &entry.Threats); err != nil {
				entry.Threats = []Threat{}
			}
		}

		result = append(result, &entry)
	}

	return result, nil
}

// SearchHistory searches scan history by file path or hash
func (h *HashStore) SearchHistory(ctx context.Context, searchQuery string) ([]*HashEntry, error) {
	if !h.enabled {
		return nil, fmt.Errorf("hash store not enabled")
	}

	query := `
		SELECT hash, file_path, first_seen, last_seen, scan_count, infected, threat_level, threats
		FROM hash_store
		WHERE hash LIKE ? OR file_path LIKE ?
		ORDER BY last_seen DESC
		LIMIT 100
	`

	pattern := "%" + searchQuery + "%"
	rows, err := h.db.QueryContext(ctx, query, pattern, pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to search history: %w", err)
	}
	defer rows.Close()

	var result []*HashEntry
	for rows.Next() {
		var entry HashEntry
		var threatsJSON string
		var threatLevel int

		err := rows.Scan(
			&entry.Hash,
			&entry.FilePath,
			&entry.FirstSeen,
			&entry.LastSeen,
			&entry.ScanCount,
			&entry.Infected,
			&threatLevel,
			&threatsJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		entry.ThreatLevel = ThreatLevel(threatLevel)
		if threatsJSON != "" {
			if err := json.Unmarshal([]byte(threatsJSON), &entry.Threats); err != nil {
				entry.Threats = []Threat{}
			}
		}

		result = append(result, &entry)
	}

	return result, nil
}

// PruneHashStore removes old entries based on retention period
func (h *HashStore) PruneHashStore(ctx context.Context, olderThan time.Duration) (int, error) {
	if !h.enabled {
		return 0, fmt.Errorf("hash store not enabled")
	}

	cutoff := time.Now().Add(-olderThan)
	result, err := h.db.ExecContext(ctx, "DELETE FROM hash_store WHERE last_seen < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to prune hash store: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}

	return int(count), nil
}

// Close closes the hash store
func (h *HashStore) Close() error {
	if h.enabled && h.db != nil {
		return h.db.Close()
	}
	return nil
}
