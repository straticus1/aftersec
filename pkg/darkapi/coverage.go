package darkapi

import (
	"aftersec/pkg/endpointreport"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"
)

var sensorNames = []string{"telemetry", "process", "network", "dns", "file_integrity", "patches", "firewall", "host_ids", "persistence", "ransomware", "self_protection", "response"}

func sourceSensor(source string) string {
	switch {
	case strings.Contains(source, "network"):
		return "network"
	case strings.Contains(source, "dns"):
		return "dns"
	case strings.Contains(source, "endpoint_security") || strings.Contains(source, "binary_authorization"):
		return "process"
	case strings.Contains(source, "file_integrity"):
		return "file_integrity"
	case strings.Contains(source, "ransomware"):
		return "ransomware"
	case strings.Contains(source, "self_protection"):
		return "self_protection"
	case strings.Contains(source, "persistence"):
		return "persistence"
	case strings.Contains(source, "yara") || strings.Contains(source, "darkscan") || strings.Contains(source, "intrusion"):
		return "host_ids"
	default:
		return "telemetry"
	}
}
func (e *Exporter) progress(tx *sql.Tx, event Event) error {
	sensor := sourceSensor(event.Event.Source)
	state := "running"
	failures := 0
	if strings.Contains(event.Event.Type, "error") || strings.Contains(event.Event.Type, "failed") {
		state = "failed"
		failures = 1
	}
	_, err := tx.Exec(`INSERT INTO darkapi_sensor_progress(sensor,state,last_event,collected,errors) VALUES(?,?,?,1,?)
 ON CONFLICT(sensor) DO UPDATE SET collected=collected+1,errors=errors+excluded.errors,
 state=CASE WHEN excluded.last_event>=last_event THEN excluded.state ELSE state END,
 last_event=MAX(last_event,excluded.last_event)`, sensor, state, event.Event.Time, failures)
	return err
}
func (e *Exporter) configuredSensors(policy map[string]any) error {
	mapping := map[string]string{"network_sensor": "network", "dns_sensor": "dns", "self_protection": "self_protection", "binary_authorization": "process", "ransomware": "ransomware"}
	for key, sensor := range mapping {
		if enabled, ok := policy[key].(bool); ok {
			_, err := e.db.Exec("INSERT INTO darkapi_sensor_config(sensor,enabled) VALUES(?,?) ON CONFLICT(sensor) DO UPDATE SET enabled=excluded.enabled", sensor, enabled)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func (e *Exporter) ReportCoverage(ctx context.Context, collect func(context.Context) ([]endpointreport.Sensor, []endpointreport.Observation)) error {
	now := time.Now().UTC()
	observed := now.Format(time.RFC3339Nano)
	states := map[string]endpointreport.Sensor{}
	for _, name := range sensorNames {
		states[name] = endpointreport.Capability(name, "unknown", "No fresh collector observation")
	}
	rows, err := e.db.Query("SELECT sensor,state,last_event,collected,errors FROM darkapi_sensor_progress")
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, state, at string
		var count, failures int64
		if err = rows.Scan(&name, &state, &at, &count, &failures); err != nil {
			rows.Close()
			return err
		}
		s := endpointreport.Sensor{Sensor: name, State: state, ObservedAt: observed, Collected: &count, Errors: &failures, Details: map[string]any{"counter_scope": "imported durable source records", "queue_device_id": e.DeviceID()}}
		stamp, parseErr := time.Parse(time.RFC3339Nano, at)
		if parseErr != nil || now.Sub(stamp) > 3*time.Minute || stamp.After(now) {
			s.State = "unknown"
			s.Reason = "No recent successful observation"
		} else if state == "running" {
			s.LastSuccessAt = at
		}
		states[name] = s
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = e.db.Query("SELECT sensor FROM darkapi_sensor_config WHERE enabled=0")
	if err != nil {
		return err
	}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		states[name] = endpointreport.Capability(name, "disabled", "Disabled in local configuration")
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	sensors, observations := collect(ctx)
	for _, s := range sensors {
		states[s.Sensor] = s
	}
	if e.source != nil {
		cursor, err := e.cursor("telemetry")
		if err == nil {
			_, err = e.source.ReportingJournal(cursor, 1)
		}
		states["telemetry"] = endpointreport.Capability("telemetry", endpointreport.State(err, nil), "Durable source reader; delivery measured separately")
		if health, ok := e.Manager.(interface{ ReportingHealth() map[string]any }); ok {
			value := states["telemetry"]
			value.Details = health.ReportingHealth()
			value.Details["counter_scope"] = "current process lifetime"
			states["telemetry"] = value
		}
	}
	response := endpointreport.Capability("response", "running", "Authenticated allowlisted command receiver")
	response.Details = map[string]any{"actions": supportedActions(), "platform": runtime.GOOS}
	states["response"] = response
	snapshots := make([]endpointreport.Sensor, 0, len(sensorNames))
	for _, name := range sensorNames {
		snapshots = append(snapshots, states[name])
	}
	if err = e.Queue(Event{Event: Evidence{Type: "sensor.health", Category: "sensor_health", Source: "aftersec_coverage", Data: map[string]any{"sensors": snapshots, "platform": runtime.GOOS}}}); err != nil {
		return err
	}
	for _, observation := range observations {
		if err = e.Queue(Event{Event: Evidence{Type: observation.Type, Category: observation.Category, Source: "aftersec_native_snapshot", Data: observation.Data, Facts: observation.Facts, Entities: observation.Entities}}); err != nil {
			return err
		}
	}
	return e.Queue(Event{Event: Evidence{Type: "delivery.canary", Category: "monitoring", Source: "aftersec_coverage", Data: map[string]any{"purpose": "end-to-end delivery freshness", "generated_at": observed}}})
}
func decodeResult(raw []byte) (map[string]any, error) {
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("invalid saved command result: %w", err)
	}
	return result, nil
}
