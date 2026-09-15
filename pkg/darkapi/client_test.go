package darkapi

import (
	"aftersec/pkg/client/storage"
	"aftersec/pkg/core"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	c, err := New(Credentials{BaseURL: server.URL, DeviceID: "dev_shared", APIKey: "test-secret", App: "aftersec"})
	if err != nil {
		t.Fatal(err)
	}
	c.http.Transport = server.Client().Transport
	return c, server
}
func TestEnrollmentAndProtectedCredentials(t *testing.T) {
	calls := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/aftersec/enroll" || r.Header.Get("X-API-Key") != "" {
			t.Error("incorrect enrollment request")
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["enrollment_token"] != "ept_test" {
			t.Error("missing token")
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "app": "aftersec", "device_id": "dev_shared", "api_key": "new-secret"})
	})
	path := filepath.Join(t.TempDir(), "private", "credentials.json")
	if err := c.Enroll(context.Background(), "ept_test", path, "test"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.DeviceID() != "dev_shared" {
		t.Fatalf("load: %v", err)
	}
	if err := c.Enroll(context.Background(), "ept_test", path, "test"); err == nil || calls != 1 {
		t.Fatal("re-enrollment overwrote identity")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("accepted public credential file")
	}
}
func TestURLAndRedirectRejection(t *testing.T) {
	for _, url := range []string{"http://api.darkapi.io", "https://user:pass@api.darkapi.io", "https://api.darkapi.io/?key=secret", "https://api.darkapi.io/v1"} {
		if _, err := NormalizeURL(url); err == nil {
			t.Errorf("accepted %s", url)
		}
	}
	if url, err := NormalizeURL("https://darkapi.io/api/"); err != nil || url != "https://api.darkapi.io" {
		t.Fatal(url, err)
	}
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://invalid.example", 302) })
	if err := c.Heartbeat(context.Background()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatal(err)
	}
}
func TestDurableQueueExactAcknowledgmentAndDeviceBinding(t *testing.T) {
	accept := false
	var sent []string
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "test-secret" || r.Header.Get("X-Device-ID") != "dev_shared" {
			t.Error("missing identity")
		}
		var body struct {
			Events []Event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		sent = nil
		for _, e := range body.Events {
			sent = append(sent, e.EventID)
		}
		ids := sent
		if !accept {
			ids = []string{"wrong-id"}
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "device_id": "dev_shared", "accepted_event_ids": ids})
	})
	path := filepath.Join(t.TempDir(), "outbox.sqlite")
	e, err := Open(nil, c, path)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := newID()
	if err = e.Queue(Event{EventID: id, Event: Evidence{Type: "firewall.rule", Severity: "high", Data: map[string]any{"rule": "test"}}}); err != nil {
		t.Fatal(err)
	}
	if err = e.Flush(context.Background()); err == nil {
		t.Fatal("accepted wrong acknowledgment")
	}
	e.Close()
	e, err = Open(nil, c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	var count int
	e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox").Scan(&count)
	if count != 1 {
		t.Fatal("lost persisted event")
	}
	c.credentials.DeviceID = "dev_other"
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox").Scan(&count)
	if count != 1 {
		t.Fatal("reassigned old device evidence")
	}
	c.credentials.DeviceID = "dev_shared"
	accept = true
	if err = e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0] != id {
		t.Fatal("retry changed event ID")
	}
	e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox").Scan(&count)
	if count != 0 {
		t.Fatal("did not acknowledge")
	}
	e.maxBytes = 1
	if err = e.Queue(Event{Event: Evidence{Type: "large"}}); err == nil {
		t.Fatal("queue limit ignored")
	}
}

type memoryManager struct {
	storage.Manager
	telemetry, commits int
}

func (m *memoryManager) LogTelemetryEvent(_, _, _, _ string) error { m.telemetry++; return nil }
func (m *memoryManager) SaveCommit(*core.SecurityState) error      { m.commits++; return nil }
func TestSensorAndPostureAdapters(t *testing.T) {
	c, _ := New(Credentials{DeviceID: "dev_shared"})
	m := &memoryManager{}
	e, err := Open(m, c, filepath.Join(t.TempDir(), "outbox.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.LogTelemetryEvent("network_sensor", "process_flow", "med", `{"remote_address":"203.0.113.9","nested":[{"api_key":"sensitive"}]}`); err != nil {
		t.Fatal(err)
	}
	if err = e.SaveCommit(&core.SecurityState{Timestamp: time.Now(), Findings: []core.Finding{{Name: "Firewall enabled", Severity: core.High, Passed: false}}}); err != nil {
		t.Fatal(err)
	}
	if m.telemetry != 1 || m.commits != 1 {
		t.Fatal("original destination not called")
	}
	rows, err := e.db.Query("SELECT payload FROM darkapi_outbox ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var b []byte
		rows.Scan(&b)
		if strings.Contains(string(b), "sensitive") {
			t.Fatal("leaked nested secret")
		}
		var event Event
		json.Unmarshal(b, &event)
		events = append(events, event)
	}
	if len(events) != 2 || events[0].Event.Severity != "medium" || events[1].Event.Category != "firewall" {
		t.Fatalf("bad adapters: %+v", events)
	}
}

func TestPolicyFingerprintDriftSurvivesRestart(t *testing.T) {
	c, _ := New(Credentials{DeviceID: "dev_shared"})
	path := filepath.Join(t.TempDir(), "outbox.sqlite")
	e, err := Open(nil, c, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.ReportPolicy(map[string]any{"strict_mode": false, "api_key": "never-upload"}); err != nil {
		t.Fatal(err)
	}
	e.Close()
	e, err = Open(nil, c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.ReportPolicy(map[string]any{"strict_mode": true, "api_key": "never-upload"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox WHERE CAST(payload AS TEXT) LIKE '%configuration_drift%'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	if err = e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox WHERE CAST(payload AS TEXT) LIKE '%never-upload%'").Scan(&count); err != nil || count != 0 {
		t.Fatal("secret in policy evidence", err)
	}
}
