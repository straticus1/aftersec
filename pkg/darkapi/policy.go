package darkapi

import (
	"aftersec/pkg/core"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
)

// ReportPolicy records an explicitly selected, non-secret configuration view.
// Enabled flags describe requested configuration, never live sensor health.
func (e *Exporter) ReportPolicy(policy map[string]any) error {
	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	safe := redact(policy)
	payload, err := json.Marshal(safe)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	if _, err = e.db.Exec("CREATE TABLE IF NOT EXISTS darkapi_policy_state(device_id TEXT PRIMARY KEY,digest TEXT NOT NULL)"); err != nil {
		return err
	}
	var previous string
	err = e.db.QueryRow("SELECT digest FROM darkapi_policy_state WHERE device_id=?", e.DeviceID()).Scan(&previous)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err = e.Queue(Event{Event: Evidence{Type: "policy.configured", Category: "policy_state", Source: "aftersec_configuration", Severity: "info", Data: map[string]any{"configured": safe, "config_sha256": digest, "scope": "requested configuration; not runtime health"}}}); err != nil {
		return err
	}
	if previous != "" && previous != digest {
		if err = e.Queue(Event{Event: Evidence{Type: "configuration.changed", Category: "configuration_drift", Source: "aftersec_configuration", Severity: "warning", Data: map[string]any{"previous_sha256": previous, "current_sha256": digest}}}); err != nil {
			return err
		}
	}
	_, err = e.db.Exec("INSERT INTO darkapi_policy_state(device_id,digest) VALUES (?,?) ON CONFLICT(device_id) DO UPDATE SET digest=excluded.digest", e.DeviceID(), digest)
	return err
}

func (e *Exporter) SaveConfig(cfg *core.Config) error {
	if err := e.Manager.SaveConfig(cfg); err != nil {
		return err
	}
	return e.Queue(Event{Event: Evidence{Type: "policy.local_saved", Category: "policy_state", Source: "aftersec_configuration", Severity: "info", Data: map[string]any{"strict_mode": cfg.StrictMode, "auto_scan": cfg.AutoScan, "finding_override_count": len(cfg.FindingOverrides)}}})
}
