package darkapi

import (
	"aftersec/pkg/core"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func stableID(value string) string {
	sum := sha1.Sum([]byte("aftersec.darkapi.v2:" + value))
	b := sum[:16]
	b[6] = b[6]&15 | 80
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func telemetryEvent(source, kind, severity, details, observed string) Event {
	data := map[string]any{}
	if json.Unmarshal([]byte(details), &data) != nil || data == nil {
		data = map[string]any{"message": details}
	}
	if kind == "" {
		kind = "telemetry"
	}
	for _, key := range []string{"timestamp", "Timestamp", "EndedAt"} {
		if raw, ok := data[key].(string); ok {
			if at, err := time.Parse(time.RFC3339Nano, raw); err == nil && !at.IsZero() {
				observed = at.UTC().Format(time.RFC3339Nano)
				break
			}
		}
	}
	evidence := Evidence{Type: kind, Source: source, Severity: Severity(severity), Time: observed, Data: redact(data)}
	if facts, ok := data["facts"].(map[string]any); ok {
		evidence.Facts = redact(facts)
	}
	if entities, ok := data["entities"].(map[string]any); ok {
		evidence.Entities = redact(entities)
	}
	if correlation, ok := data["correlation_id"].(string); ok {
		evidence.CorrelationID = correlation
	}
	return Event{Event: evidence}
}
func postureEvents(state *core.SecurityState) []Event {
	events := make([]Event, 0, len(state.Findings))
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
		events = append(events, Event{Event: Evidence{Type: "posture.finding", Category: category, Source: "aftersec_posture", Severity: Severity(string(finding.Severity)), Time: state.Timestamp.UTC().Format(time.RFC3339Nano), Data: redact(data), Entities: finding.Entities, Facts: finding.Facts}})
	}
	return events
}
func (e *Exporter) cursor(stream string) (int64, error) {
	var sequence int64
	err := e.db.QueryRow("SELECT sequence FROM darkapi_source_cursors WHERE source_id=? AND stream=?", e.sourceID, stream).Scan(&sequence)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return sequence, err
}

// SyncSource imports a bounded historical or live page. Destination rows and both
// cursors commit together. A crash before commit repeats the same source IDs.
func (e *Exporter) SyncSource() (int, error) {
	if e.source == nil {
		return 0, nil
	}
	e.syncMu.Lock()
	defer e.syncMu.Unlock()
	journalCursor, err := e.cursor("telemetry")
	if err != nil {
		return 0, err
	}
	commitCursor, err := e.cursor("posture")
	if err != nil {
		return 0, err
	}
	records, err := e.source.ReportingJournal(journalCursor, 100)
	if err != nil {
		return 0, err
	}
	commits, err := e.source.ReportingCommits(commitCursor, 10)
	if err != nil {
		return 0, err
	}
	if len(records)+len(commits) == 0 {
		return 0, nil
	}
	tx, err := e.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, record := range records {
		var saved struct {
			Timestamp    string `json:"timestamp"`
			Source       string `json:"source"`
			EventType    string `json:"event_type"`
			Severity     string `json:"severity"`
			Details      string `json:"details"`
			BootID       string `json:"boot_id"`
			AgentVersion string `json:"agent_version"`
		}
		if err = json.Unmarshal(record.Payload, &saved); err != nil {
			if err = e.quarantineSource(tx, "telemetry", record.Sequence, record.Payload); err != nil {
				return 0, err
			}
			journalCursor = record.Sequence
			continue
		}
		event := telemetryEvent(saved.Source, saved.EventType, saved.Severity, saved.Details, saved.Timestamp)
		event.EventID = stableID(fmt.Sprintf("%s:%s:telemetry:%d", e.DeviceID(), e.sourceID, record.Sequence))
		event.Event.SchemaVersion = 2
		event.Event.StreamID = e.sourceID + ":telemetry"
		event.Event.Sequence = record.Sequence
		event.Event.BootID = saved.BootID
		event.Event.AgentVersion = saved.AgentVersion
		event.Event.CollectionStatus = "observed"
		if err = e.enqueue(tx, event); err != nil {
			return 0, err
		}
		if err = e.progress(tx, event); err != nil {
			return 0, err
		}
		journalCursor = record.Sequence
	}
	for _, row := range commits {
		id, ok := row["id"].(int64)
		if !ok {
			return 0, fmt.Errorf("invalid posture source cursor")
		}
		raw, ok := row["data"].(string)
		if !ok {
			if b, yes := row["data"].([]byte); yes {
				raw = string(b)
			} else {
				return 0, fmt.Errorf("invalid posture source payload")
			}
		}
		var state core.SecurityState
		if err = json.Unmarshal([]byte(raw), &state); err != nil {
			if err = e.quarantineSource(tx, "posture", id, []byte(raw)); err != nil {
				return 0, err
			}
			commitCursor = id
			continue
		}
		for index, event := range postureEvents(&state) {
			event.EventID = stableID(fmt.Sprintf("%s:%s:posture:%d:%d", e.DeviceID(), e.sourceID, id, index))
			event.Event.SchemaVersion = 2
			event.Event.StreamID = fmt.Sprintf("%s:posture:%d", e.sourceID, index)
			event.Event.Sequence = id
			event.Event.CollectionStatus = "observed"
			if err = e.enqueue(tx, event); err != nil {
				return 0, err
			}
		}
		commitCursor = id
	}
	for stream, sequence := range map[string]int64{"telemetry": journalCursor, "posture": commitCursor} {
		if _, err = tx.Exec("INSERT INTO darkapi_source_cursors(source_id,stream,sequence) VALUES(?,?,?) ON CONFLICT(source_id,stream) DO UPDATE SET sequence=excluded.sequence", e.sourceID, stream, sequence); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(records) + len(commits), nil
}
func (e *Exporter) Stats() (map[string]any, error) {
	var queued, accepted, rejected, pending, quarantined, bytes int64
	if err := e.db.QueryRow("SELECT queued_total,accepted_total,rejected_attempts FROM darkapi_delivery_stats WHERE device_id=?", e.DeviceID()).Scan(&queued, &accepted, &rejected); err != nil {
		return nil, err
	}
	if err := e.db.QueryRow("SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM darkapi_outbox WHERE device_id=?", e.DeviceID()).Scan(&pending, &bytes); err != nil {
		return nil, err
	}
	if err := e.db.QueryRow("SELECT COUNT(*) FROM darkapi_quarantine WHERE device_id=?", e.DeviceID()).Scan(&quarantined); err != nil {
		return nil, err
	}
	return map[string]any{"device_id": e.DeviceID(), "queued_total": queued, "accepted_total": accepted, "rejected_attempts": rejected, "pending_events": pending, "pending_bytes": bytes, "quarantined_events": quarantined, "limit_bytes": e.maxBytes}, nil
}
func (e *Exporter) Quarantined() ([]map[string]any, error) {
	rows, err := e.db.Query("SELECT event_id,reason,created_at FROM darkapi_quarantine WHERE device_id=? ORDER BY created_at LIMIT 100", e.DeviceID())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := []map[string]any{}
	for rows.Next() {
		var id, reason, at string
		if err = rows.Scan(&id, &reason, &at); err != nil {
			return nil, err
		}
		results = append(results, map[string]any{"event_id": id, "reason": reason, "created_at": at})
	}
	return results, rows.Err()
}
func (e *Exporter) Requeue(id string) error {
	e.flushMu.Lock()
	defer e.flushMu.Unlock()
	tx, err := e.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("INSERT INTO darkapi_outbox(device_id,event_id,payload) SELECT device_id,event_id,payload FROM darkapi_quarantine WHERE device_id=? AND event_id=? AND length(payload)<=262144 AND reason NOT LIKE 'invalid source%'", e.DeviceID(), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("quarantined event missing or exceeds upload size limit")
	}
	if _, err = tx.Exec("DELETE FROM darkapi_quarantine WHERE device_id=? AND event_id=?", e.DeviceID(), id); err != nil {
		return err
	}
	return tx.Commit()
}

// Invalid source records remain local and cannot be requeued as upload envelopes.
// Their quarantine and cursor advance are committed in the same transaction.
func (e *Exporter) quarantineSource(tx *sql.Tx, stream string, sequence int64, raw []byte) error {
	var used int64
	if err := tx.QueryRow("SELECT (SELECT COALESCE(SUM(length(payload)),0) FROM darkapi_outbox)+(SELECT COALESCE(SUM(length(payload)),0) FROM darkapi_quarantine)").Scan(&used); err != nil {
		return err
	}
	if used+int64(len(raw)) > e.maxBytes {
		return fmt.Errorf("DarkAPI queue full; invalid source retained at source")
	}
	id := stableID(fmt.Sprintf("%s:%s:%s:%d:invalid", e.DeviceID(), e.sourceID, stream, sequence))
	if _, err := tx.Exec("INSERT INTO darkapi_quarantine(event_id,device_id,payload,reason,created_at) VALUES(?,?,?,?,?)", id, e.DeviceID(), raw, "invalid source JSON: "+stream, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	_, err := tx.Exec("UPDATE darkapi_delivery_stats SET queued_total=queued_total+1,rejected_attempts=rejected_attempts+1 WHERE device_id=?", e.DeviceID())
	return err
}
