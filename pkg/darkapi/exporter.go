package darkapi

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"aftersec/pkg/reportmeta"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Exporter advances only its own source cursor, atomically with destination rows.
// The original enterprise exporter's acknowledged/synced fields are never changed.
type Exporter struct {
	storage.Manager
	db                            *sql.DB
	client                        *Client
	source                        storage.ReportingSource
	sourceID, streamID            string
	mu, flushMu, policyMu, syncMu sync.Mutex
	maxBytes                      int64
}

func Open(manager storage.Manager, client *Client, path string) (*Exporter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0)) {
		return nil, fmt.Errorf("queue must be a private regular file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL&_synchronous=FULL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	e := &Exporter{Manager: manager, db: db, client: client, maxBytes: 100 << 20}
	if err = e.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	if source, ok := manager.(storage.ReportingSource); ok {
		e.source = source
		e.sourceID, err = source.ReportingIdentity()
		if err != nil {
			db.Close()
			return nil, err
		}
		var bound string
		if _, err = db.Exec("INSERT OR IGNORE INTO darkapi_source_bindings(source_id,device_id) VALUES(?,?)", e.sourceID, e.DeviceID()); err == nil {
			err = db.QueryRow("SELECT device_id FROM darkapi_source_bindings WHERE source_id=?", e.sourceID).Scan(&bound)
		}
		if err != nil || bound != e.DeviceID() {
			db.Close()
			return nil, fmt.Errorf("source journal is bound to another device or cannot be bound")
		}
	}
	return e, nil
}
func (e *Exporter) initialize() error {
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS darkapi_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id TEXT NOT NULL,event_id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS darkapi_quarantine(event_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,payload BLOB NOT NULL,reason TEXT NOT NULL,created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS darkapi_source_bindings(source_id TEXT PRIMARY KEY,device_id TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS darkapi_source_cursors(source_id TEXT NOT NULL,stream TEXT NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(source_id,stream))`,
		`CREATE TABLE IF NOT EXISTS darkapi_delivery_stats(device_id TEXT PRIMARY KEY,queued_total INTEGER NOT NULL DEFAULT 0,accepted_total INTEGER NOT NULL DEFAULT 0,rejected_attempts INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS darkapi_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)`,
	} {
		if _, err := e.db.Exec(q); err != nil {
			return err
		}
	}
	id, err := newID()
	if err != nil {
		return err
	}
	if _, err = e.db.Exec("INSERT OR IGNORE INTO darkapi_metadata(key,value) VALUES('stream_id',?)", id); err != nil {
		return err
	}
	if err = e.db.QueryRow("SELECT value FROM darkapi_metadata WHERE key='stream_id'").Scan(&e.streamID); err != nil {
		return err
	}
	_, err = e.db.Exec("INSERT OR IGNORE INTO darkapi_delivery_stats(device_id,queued_total) SELECT ?,COUNT(*) FROM darkapi_outbox WHERE device_id=?", e.DeviceID(), e.DeviceID())
	return err
}
func (e *Exporter) DeviceID() string { return e.client.DeviceID() }
func (e *Exporter) Close() error     { return e.db.Close() }

func (e *Exporter) enqueue(tx *sql.Tx, event Event) error {
	if event.EventID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		event.EventID = id
	}
	if event.Event.Time == "" && event.Event.SchemaVersion == 0 {
		event.Event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if event.Event.SchemaVersion == 0 {
		event.Event.SchemaVersion = 2
		event.Event.BootID = reportmeta.BootID()
		event.Event.AgentVersion = reportmeta.Version()
		event.Event.StreamID = e.streamID
		event.Event.CollectionStatus = "observed"
		if err := tx.QueryRow("SELECT queued_total+1 FROM darkapi_delivery_stats WHERE device_id=?", e.DeviceID()).Scan(&event.Event.Sequence); err != nil {
			return err
		}
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	var existing []byte
	err = tx.QueryRow("SELECT payload FROM darkapi_outbox WHERE event_id=? UNION ALL SELECT payload FROM darkapi_quarantine WHERE event_id=?", event.EventID, event.EventID).Scan(&existing)
	if err == nil {
		if string(existing) != string(payload) {
			return fmt.Errorf("conflicting local event ID")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	var used int64
	if err = tx.QueryRow("SELECT (SELECT COALESCE(SUM(length(payload)),0) FROM darkapi_outbox)+(SELECT COALESCE(SUM(length(payload)),0) FROM darkapi_quarantine)").Scan(&used); err != nil {
		return err
	}
	if used+int64(len(payload)) > e.maxBytes {
		return fmt.Errorf("DarkAPI queue full; source cursor and pending evidence retained")
	}
	if len(payload) > 256<<10 {
		if _, err = tx.Exec("INSERT INTO darkapi_quarantine(event_id,device_id,payload,reason,created_at) VALUES(?,?,?,?,?)", event.EventID, e.DeviceID(), payload, "event exceeds 256 KiB", time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE darkapi_delivery_stats SET rejected_attempts=rejected_attempts+1 WHERE device_id=?", e.DeviceID()); err != nil {
			return err
		}
	} else if _, err = tx.Exec("INSERT INTO darkapi_outbox(device_id,event_id,payload) VALUES(?,?,?)", e.DeviceID(), event.EventID, payload); err != nil {
		return err
	}
	_, err = tx.Exec("UPDATE darkapi_delivery_stats SET queued_total=queued_total+1 WHERE device_id=?", e.DeviceID())
	return err
}
func (e *Exporter) Queue(event Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = e.enqueue(tx, event); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Exporter) ack(ids []int64) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		result, err := tx.Exec("DELETE FROM darkapi_outbox WHERE id=? AND device_id=?", id, e.DeviceID())
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE darkapi_delivery_stats SET accepted_total=accepted_total+? WHERE device_id=?", n, e.DeviceID()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (e *Exporter) quarantine(id int64, reason string) error {
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("INSERT INTO darkapi_quarantine(event_id,device_id,payload,reason,created_at) SELECT event_id,device_id,payload,?,? FROM darkapi_outbox WHERE id=? AND device_id=?", reason, time.Now().UTC().Format(time.RFC3339Nano), id, e.DeviceID()); err != nil {
		return err
	}
	if _, err = tx.Exec("DELETE FROM darkapi_outbox WHERE id=? AND device_id=?", id, e.DeviceID()); err != nil {
		return err
	}
	if _, err = tx.Exec("UPDATE darkapi_delivery_stats SET rejected_attempts=rejected_attempts+1 WHERE device_id=?", e.DeviceID()); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Exporter) Flush(ctx context.Context) error {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	rows, err := e.db.Query("SELECT id,payload FROM darkapi_outbox WHERE device_id=? ORDER BY id LIMIT 100", e.DeviceID())
	if err != nil {
		return err
	}
	var events []Event
	var ids []int64
	total := 0
	for rows.Next() {
		var id int64
		var b []byte
		if err = rows.Scan(&id, &b); err != nil {
			rows.Close()
			return err
		}
		if total+len(b) > 900<<10 {
			break
		}
		var event Event
		if err = json.Unmarshal(b, &event); err != nil {
			rows.Close()
			return err
		}
		events = append(events, event)
		ids = append(ids, id)
		total += len(b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	if err = e.client.Send(ctx, events); err == nil {
		return e.ack(ids)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || !apiErr.Permanent() {
		return err
	}
	// Isolate a permanently rejected record; never quarantine credentials, rate
	// limits, timeouts, server outages or malformed acknowledgment responses.
	for i, event := range events {
		if err = e.client.Send(ctx, []Event{event}); err == nil {
			if err = e.ack([]int64{ids[i]}); err != nil {
				return err
			}
			continue
		}
		if !errors.As(err, &apiErr) || !apiErr.Permanent() {
			return err
		}
		if err = e.quarantine(ids[i], apiErr.Error()); err != nil {
			return err
		}
	}
	return nil
}
func (e *Exporter) LogTelemetryEvent(source, kind, severity, details string) error {
	if e.source != nil {
		return e.Manager.LogTelemetryEvent(source, kind, severity, details)
	}
	// Non-replayable managers receive a durable write-ahead copy before delegation.
	if err := e.Queue(telemetryEvent(source, kind, severity, details, "")); err != nil {
		return err
	}
	return e.Manager.LogTelemetryEvent(source, kind, severity, details)
}
func (e *Exporter) SaveCommit(state *core.SecurityState) error {
	if e.source != nil {
		return e.Manager.SaveCommit(state)
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range postureEvents(state) {
		if err = e.enqueue(tx, event); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	return e.Manager.SaveCommit(state)
}
func (e *Exporter) Run(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var reportAt, nextDelivery time.Time
	attempt := 0
	for {
		if ctx.Err() != nil {
			return
		}
		if _, err := e.SyncSource(); err != nil {
			log.Printf("DarkAPI source retained: %v", err)
		}
		now := time.Now()
		if !now.Before(reportAt) {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			if err := e.Queue(Event{Event: Evidence{Type: "agent.resources", Category: "agent_resources", Source: "aftersec_exporter", Severity: "info", Data: map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "goroutines": runtime.NumGoroutine(), "heap_bytes": mem.Alloc}}}); err != nil {
				log.Printf("DarkAPI metrics: %v", err)
			}
			if stats, err := e.Stats(); err == nil {
				if err = e.Queue(Event{Event: Evidence{Type: "exporter.queue", Category: "monitoring", Source: "aftersec_exporter", Severity: "info", Data: stats}}); err != nil {
					log.Printf("DarkAPI queue metrics: %v", err)
				}
			}
			if err := e.client.Heartbeat(ctx); err != nil {
				log.Printf("DarkAPI heartbeat: %v", err)
			}
			reportAt = now.Add(30 * time.Second)
		}
		if !now.Before(nextDelivery) {
			var deliveryErr error
			for batch := 0; batch < 20 && ctx.Err() == nil; batch++ {
				if deliveryErr = e.Flush(ctx); deliveryErr != nil {
					break
				}
				var pending int
				if err := e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox WHERE device_id=?", e.DeviceID()).Scan(&pending); err != nil || pending == 0 {
					break
				}
			}
			if deliveryErr != nil {
				attempt++
				var hint time.Duration
				var apiErr *APIError
				if errors.As(deliveryErr, &apiErr) {
					hint = apiErr.RetryAfter
				}
				nextDelivery = time.Now().Add(retryDelay(attempt, hint))
				log.Printf("DarkAPI export retained for retry: %v", deliveryErr)
			} else {
				attempt = 0
				nextDelivery = time.Time{}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func FromEnvironment(manager storage.Manager) (*Exporter, error) {
	path := os.Getenv("AFTERSEC_DARKAPI_CREDENTIALS")
	if path == "" {
		return nil, nil
	}
	client, err := Load(path)
	if err != nil {
		return nil, err
	}
	return Open(manager, client, filepath.Join(filepath.Dir(path), "darkapi-outbox.sqlite"))
}
