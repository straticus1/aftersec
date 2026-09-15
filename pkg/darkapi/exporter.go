package darkapi

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Exporter maintains its own durable destination queue. It never acknowledges
// the existing enterprise exporter or consumes its shared synced flag.
type Exporter struct {
	storage.Manager
	db       *sql.DB
	client   *Client
	mu       sync.Mutex
	flushMu  sync.Mutex
	policyMu sync.Mutex
	maxBytes int64
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
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS darkapi_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,device_id TEXT NOT NULL,event_id TEXT NOT NULL UNIQUE,payload BLOB NOT NULL)`); err != nil {
		db.Close()
		return nil, err
	}
	return &Exporter{Manager: manager, db: db, client: client, maxBytes: 100 << 20}, nil
}
func (e *Exporter) DeviceID() string { return e.client.DeviceID() }
func (e *Exporter) Close() error     { return e.db.Close() }
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}
func (e *Exporter) Queue(event Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if event.EventID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		event.EventID = id
	}
	if event.Event.Time == "" {
		event.Event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(payload) > 256<<10 {
		return fmt.Errorf("event exceeds 256 KiB")
	}
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var used int64
	if err := tx.QueryRow("SELECT COALESCE(SUM(length(payload)),0) FROM darkapi_outbox").Scan(&used); err != nil {
		return err
	}
	if used+int64(len(payload)) > e.maxBytes {
		return fmt.Errorf("DarkAPI queue full; pending evidence retained")
	}
	if _, err := tx.Exec("INSERT INTO darkapi_outbox(device_id,event_id,payload) VALUES (?,?,?)", e.client.DeviceID(), event.EventID, payload); err != nil {
		return err
	}
	return tx.Commit()
}
func (e *Exporter) Flush(ctx context.Context) error {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	rows, err := e.db.Query("SELECT id,payload FROM darkapi_outbox WHERE device_id=? ORDER BY id LIMIT 100", e.client.DeviceID())
	if err != nil {
		return err
	}
	var events []Event
	var ids []int64
	total := 0
	for rows.Next() {
		var id int64
		var b []byte
		if err := rows.Scan(&id, &b); err != nil {
			rows.Close()
			return err
		}
		if total+len(b) > 900<<10 {
			break
		}
		var event Event
		if err := json.Unmarshal(b, &event); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
		events = append(events, event)
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
	if err := e.client.Send(ctx, events); err != nil {
		return err
	}
	// The server's exact ID acknowledgment is verified before deleting only this batch.
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec("DELETE FROM darkapi_outbox WHERE id=? AND device_id=?", id, e.client.DeviceID()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func Severity(s string) string {
	switch s {
	case "critical":
		return s
	case "high", "very-high":
		return "high"
	case "medium", "med":
		return "medium"
	case "low":
		return s
	case "warning":
		return s
	default:
		return "info"
	}
}

// redact removes credential-bearing fields before upload; it never executes remediation content.
func redact(data map[string]any) map[string]any {
	result := make(map[string]any, len(data))
	for key, value := range data {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "api_key") || strings.Contains(lower, "private_key") {
			result[key] = "[redacted]"
			continue
		}
		value = redactValue(value)
		result[key] = value
	}
	return result
}
func redactValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return redact(v)
	case []any:
		result := make([]any, len(v))
		for i, child := range v {
			result[i] = redactValue(child)
		}
		return result
	default:
		return value
	}
}
func (e *Exporter) LogTelemetryEvent(source, eventType, severity, details string) error {
	if err := e.Manager.LogTelemetryEvent(source, eventType, severity, details); err != nil {
		return err
	}
	data := map[string]any{}
	if json.Unmarshal([]byte(details), &data) != nil || data == nil {
		data = map[string]any{"message": details}
	}
	if eventType == "" {
		eventType = "telemetry"
	}
	observed := ""
	for _, key := range []string{"timestamp", "Timestamp", "EndedAt"} {
		if raw, ok := data[key].(string); ok {
			if parsed, err := time.Parse(time.RFC3339Nano, raw); err == nil && !parsed.IsZero() {
				observed = parsed.UTC().Format(time.RFC3339Nano)
				break
			}
		}
	}
	return e.Queue(Event{Event: Evidence{Type: eventType, Source: source, Severity: Severity(severity), Time: observed, Data: redact(data)}})
}
func (e *Exporter) SaveCommit(state *core.SecurityState) error {
	if err := e.Manager.SaveCommit(state); err != nil {
		return err
	}
	for _, finding := range state.Findings {
		data := map[string]any{"name": finding.Name, "category": finding.Category, "passed": finding.Passed, "current": finding.CurrentVal, "expected": finding.ExpectedVal, "description": finding.Description, "cis_benchmark": finding.CISBenchmark}
		category := "compliance"
		name := strings.ToLower(finding.Category + " " + finding.Name)
		switch {
		case strings.Contains(name, "patch") || strings.Contains(name, "update"):
			category = "patches"
		case strings.Contains(name, "firewall"):
			category = "firewall"
		case strings.Contains(name, "intrusion") || strings.Contains(name, "host ids"):
			category = "host_ids"
		}
		if err := e.Queue(Event{Event: Evidence{Type: "posture.finding", Category: category, Source: "aftersec_posture", Severity: Severity(string(finding.Severity)), Time: state.Timestamp.UTC().Format(time.RFC3339Nano), Data: redact(data)}}); err != nil {
			return err
		}
	}
	return nil
}
func (e *Exporter) Run(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		if err := e.Queue(Event{Event: Evidence{Type: "agent.resources", Category: "agent_resources", Source: "aftersec_exporter", Severity: "info", Data: map[string]any{"goos": runtime.GOOS, "goarch": runtime.GOARCH, "goroutines": runtime.NumGoroutine(), "heap_bytes": mem.Alloc}}}); err != nil {
			log.Printf("DarkAPI reporting: %v", err)
		}
		var pending, bytes int64
		if err := e.db.QueryRow("SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM darkapi_outbox WHERE device_id=?", e.DeviceID()).Scan(&pending, &bytes); err == nil {
			if err = e.Queue(Event{Event: Evidence{Type: "exporter.queue", Category: "monitoring", Source: "aftersec_exporter", Severity: "info", Data: map[string]any{"pending_events": pending, "pending_bytes": bytes, "limit_bytes": e.maxBytes}}}); err != nil {
				log.Printf("DarkAPI queue metrics: %v", err)
			}
		}
		if err := e.client.Heartbeat(ctx); err != nil {
			log.Printf("DarkAPI heartbeat: %v", err)
		}
		// Drain up to 2,000 events each cycle; bound work so heartbeats and shutdown remain responsive.
		for batch := 0; batch < 20; batch++ {
			if err := e.Flush(ctx); err != nil {
				log.Printf("DarkAPI export retained for retry: %v", err)
				break
			}
			var pending int
			if err := e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox WHERE device_id=?", e.DeviceID()).Scan(&pending); err != nil || pending == 0 {
				break
			}
			if ctx.Err() != nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// FromEnvironment enables reporting only when a protected credential file is explicitly configured.
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
