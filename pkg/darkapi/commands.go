package darkapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type ResponseCommand struct {
	ID         string         `json:"id"`
	DeviceID   string         `json:"device_id"`
	App        string         `json:"app"`
	Action     string         `json:"action"`
	Params     map[string]any `json:"params"`
	ExpiresAt  time.Time      `json:"expires_at"`
	LeaseToken string         `json:"lease_token"`
}

func supportedActions() []string {
	actions := []string{"collect_status", "delivery_canary"}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		actions = append(actions, "list_persistence")
	}
	return actions
}
func supports(action string) bool {
	for _, a := range supportedActions() {
		if a == action {
			return true
		}
	}
	return false
}
func persistenceInventory() (map[string]any, error) {
	roots := []string{"/etc/systemd/system", "/etc/cron.d", "/etc/init.d"}
	if runtime.GOOS == "darwin" {
		roots = []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"}
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("persistence inventory unsupported")
	}
	items := []map[string]any{}
	truncated := false
	for _, root := range roots {
		f, err := os.Open(root)
		if err != nil {
			items = append(items, map[string]any{"path": root, "error": err.Error()})
			continue
		}
		entries, err := f.ReadDir(101)
		f.Close()
		if err != nil && len(entries) == 0 {
			items = append(items, map[string]any{"path": root, "error": err.Error()})
			continue
		}
		if len(entries) > 100 {
			entries = entries[:100]
			truncated = true
		}
		for _, entry := range entries {
			items = append(items, map[string]any{"path": filepath.Join(root, entry.Name()), "directory": entry.IsDir(), "symlink": entry.Type()&os.ModeSymlink != 0})
		}
	}
	return map[string]any{"entries": items, "truncated": truncated, "scope": "system persistence entry names; files are not executed or read"}, nil
}
func (e *Exporter) PollCommands(ctx context.Context) error {
	e.commandMu.Lock()
	defer e.commandMu.Unlock()
	var response struct {
		Command *ResponseCommand `json:"command"`
	}
	if err := e.client.request(ctx, "POST", "/api/v1/endpoints/aftersec/commands/claim", map[string]any{}, &response, true); err != nil {
		return err
	}
	command := response.Command
	if command == nil {
		return nil
	}
	if command.DeviceID != e.DeviceID() || command.App != "aftersec" || len(command.ID) != 36 || len(command.LeaseToken) != 36 || len(command.Params) != 0 || !command.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("invalid or expired endpoint command")
	}
	var raw []byte
	var status, action string
	err := e.db.QueryRow("SELECT action,result,status FROM darkapi_command_results WHERE id=?", command.ID).Scan(&action, &raw, &status)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil && action != command.Action {
		return fmt.Errorf("command ID reused with different action")
	}
	if err == sql.ErrNoRows {
		err = nil
		result := map[string]any{}
		status = "succeeded"
		if !supports(command.Action) {
			status = "failed"
			result["error"] = "unsupported action"
		} else {
			switch command.Action {
			case "collect_status":
				result, err = e.Stats()
			case "list_persistence":
				result, err = persistenceInventory()
			case "delivery_canary":
				result["event_id"] = command.ID
			}
			if err != nil {
				status = "failed"
				result = map[string]any{"error": err.Error()}
			}
		}
		if time.Now().After(command.ExpiresAt) {
			return fmt.Errorf("command expired before result commit")
		}
		raw, err = json.Marshal(redact(result))
		if err != nil {
			return err
		}
		if len(raw) > 65536 {
			status = "failed"
			raw = []byte(`{"error":"result exceeds 64 KiB"}`)
		}
		tx, err := e.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if status == "succeeded" && command.Action == "delivery_canary" {
			event := Event{EventID: command.ID, Event: Evidence{Type: "delivery.canary", Category: "monitoring", Source: "aftersec_response", Data: map[string]any{"command_id": command.ID}}}
			if err = e.enqueue(tx, event); err != nil {
				return err
			}
		}
		if _, err = tx.Exec("INSERT INTO darkapi_command_results(id,action,result,status) VALUES(?,?,?,?)", command.ID, command.Action, raw, status); err != nil {
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	result, err := decodeResult(raw)
	if err != nil {
		return err
	}
	ack := map[string]any{"lease_token": command.LeaseToken, "status": status, "result": result}
	var accepted struct {
		Success   bool   `json:"success"`
		CommandID string `json:"command_id"`
	}
	if err = e.client.request(ctx, "POST", "/api/v1/endpoints/aftersec/commands/"+command.ID+"/ack", ack, &accepted, true); err != nil {
		return err
	}
	if !accepted.Success || !strings.EqualFold(accepted.CommandID, command.ID) {
		return fmt.Errorf("command acknowledgment mismatch")
	}
	return nil
}
