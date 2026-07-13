// Package eventjournal provides durable, tamper-evident telemetry storage.
//
// Threats: records are hash chained and verified on open/read to expose payload
// modification, deletion, and reordering. Capacity exhaustion fails closed and
// preserves existing evidence. This package does not protect against an attacker
// who can replace the complete database and its future external chain anchor.
package eventjournal

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	_ "github.com/mattn/go-sqlite3"
)

var (
	ErrFull       = errors.New("event journal full")
	ErrTampered   = errors.New("event journal hash chain invalid")
	ErrInvalidAck = errors.New("invalid event journal acknowledgment")
)

type Record struct {
	Sequence int64
	Payload  []byte
	PrevHash []byte
	Hash     []byte
}

type Journal struct {
	db       *sql.DB
	maxBytes int64
	mu       sync.Mutex
}

func Open(path string, maxBytes int64) (*Journal, error) {
	if path == "" {
		return nil, fmt.Errorf("journal path is required")
	}
	if maxBytes <= 0 {
		return nil, fmt.Errorf("journal capacity must be positive")
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open event journal: %w", err)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable event journal WAL: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS event_journal (
		sequence INTEGER PRIMARY KEY AUTOINCREMENT,
		payload BLOB NOT NULL,
		prev_hash BLOB NOT NULL,
		hash BLOB NOT NULL,
		acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1))
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize event journal: %w", err)
	}
	j := &Journal{db: db, maxBytes: maxBytes}
	if err := j.Verify(); err != nil {
		db.Close()
		return nil, err
	}
	return j, nil
}

func (j *Journal) Close() error {
	return j.db.Close()
}

func recordHash(prevHash, payload []byte) []byte {
	h := sha256.New()
	h.Write(prevHash)
	h.Write(payload)
	return h.Sum(nil)
}

func (j *Journal) Append(payload []byte) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	tx, err := j.db.Begin()
	if err != nil {
		return Record{}, fmt.Errorf("begin journal append: %w", err)
	}
	defer tx.Rollback()

	var used int64
	if err := tx.QueryRow("SELECT COALESCE(SUM(length(payload)), 0) FROM event_journal").Scan(&used); err != nil {
		return Record{}, fmt.Errorf("measure event journal: %w", err)
	}
	if int64(len(payload)) > j.maxBytes-used {
		return Record{}, ErrFull
	}

	var prevHash []byte
	err = tx.QueryRow("SELECT hash FROM event_journal ORDER BY sequence DESC LIMIT 1").Scan(&prevHash)
	if errors.Is(err, sql.ErrNoRows) {
		prevHash = []byte{}
	} else if err != nil {
		return Record{}, fmt.Errorf("read event journal head: %w", err)
	}
	hash := recordHash(prevHash, payload)
	result, err := tx.Exec("INSERT INTO event_journal (payload, prev_hash, hash) VALUES (?, ?, ?)", payload, prevHash, hash)
	if err != nil {
		return Record{}, fmt.Errorf("append event journal: %w", err)
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return Record{}, fmt.Errorf("read event journal sequence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Record{}, fmt.Errorf("commit event journal append: %w", err)
	}
	return Record{Sequence: sequence, Payload: bytes.Clone(payload), PrevHash: bytes.Clone(prevHash), Hash: hash}, nil
}

func (j *Journal) Verify() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	rows, err := j.db.Query("SELECT sequence, payload, prev_hash, hash FROM event_journal ORDER BY sequence")
	if err != nil {
		return fmt.Errorf("read event journal: %w", err)
	}
	defer rows.Close()

	var previousSequence int64
	var previousHash []byte
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.Sequence, &record.Payload, &record.PrevHash, &record.Hash); err != nil {
			return fmt.Errorf("decode event journal: %w", err)
		}
		if record.Sequence != previousSequence+1 ||
			!bytes.Equal(record.PrevHash, previousHash) ||
			!bytes.Equal(record.Hash, recordHash(record.PrevHash, record.Payload)) {
			return ErrTampered
		}
		previousSequence = record.Sequence
		previousHash = bytes.Clone(record.Hash)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate event journal: %w", err)
	}
	return nil
}

func (j *Journal) Pending(limit int) ([]Record, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("pending limit must be positive")
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	rows, err := j.db.Query("SELECT sequence, payload, prev_hash, hash FROM event_journal WHERE acknowledged = 0 ORDER BY sequence LIMIT ?", limit)
	if err != nil {
		return nil, fmt.Errorf("read pending event journal: %w", err)
	}
	defer rows.Close()
	var records []Record
	for rows.Next() {
		var record Record
		if err := rows.Scan(&record.Sequence, &record.Payload, &record.PrevHash, &record.Hash); err != nil {
			return nil, fmt.Errorf("decode pending event journal: %w", err)
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (j *Journal) Acknowledge(sequence int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	tx, err := j.db.Begin()
	if err != nil {
		return fmt.Errorf("begin journal acknowledgment: %w", err)
	}
	defer tx.Rollback()
	var highest, acknowledged int64
	if err := tx.QueryRow("SELECT COALESCE(MAX(sequence), 0), COALESCE(MAX(CASE WHEN acknowledged = 1 THEN sequence ELSE 0 END), 0) FROM event_journal").Scan(&highest, &acknowledged); err != nil {
		return fmt.Errorf("read journal acknowledgment cursor: %w", err)
	}
	if sequence < acknowledged || sequence > highest {
		return ErrInvalidAck
	}
	if _, err := tx.Exec("UPDATE event_journal SET acknowledged = 1 WHERE sequence > ? AND sequence <= ?", acknowledged, sequence); err != nil {
		return fmt.Errorf("advance journal acknowledgment: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit journal acknowledgment: %w", err)
	}
	return nil
}
