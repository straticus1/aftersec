package darkapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCommandReceiptSurvivesRestartAndLostAck(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	ack := 0
	c, _ := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/endpoints/aftersec/commands/claim" {
			json.NewEncoder(w).Encode(map[string]any{"command": ResponseCommand{ID: id, DeviceID: "dev_shared", App: "aftersec", Action: "delivery_canary", ExpiresAt: time.Now().Add(time.Minute), LeaseToken: id}})
			return
		}
		ack++
		if ack == 1 {
			http.Error(w, "lost", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "command_id": id})
	})
	path := filepath.Join(t.TempDir(), "queue.db")
	e, err := Open(nil, c, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = e.PollCommands(context.Background()); err == nil {
		t.Fatal("lost ack should fail")
	}
	e.Close()
	e, err = Open(nil, c, path)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.PollCommands(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = e.db.QueryRow("SELECT COUNT(*) FROM darkapi_outbox").Scan(&count); err != nil || count != 1 {
		t.Fatal("canary duplicated", count, err)
	}
	if err = e.db.QueryRow("SELECT COUNT(*) FROM darkapi_command_results").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}
func TestRotationResumesProtectedPendingKey(t *testing.T) {
	begins, confirms := 0, 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/endpoints/aftersec/credential-rotations" {
			begins++
			json.NewEncoder(w).Encode(map[string]any{"rotation_id": "11111111-1111-4111-8111-111111111111", "api_key": "new", "device_id": "dev_shared", "app": "aftersec"})
			return
		}
		confirms++
		if r.Header.Get("X-API-Key") != "new" {
			t.Error("new key required")
		}
		if confirms == 1 {
			http.Error(w, "lost", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "device_id": "dev_shared"})
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := writePrivate(path, Credentials{BaseURL: server.URL, DeviceID: "dev_shared", APIKey: "old", App: "aftersec"}, true); err != nil {
		t.Fatal(err)
	}
	if err := RotateCredentials(context.Background(), path); err == nil {
		t.Fatal("expected lost acknowledgment")
	}
	if err := RotateCredentials(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil || loaded.credentials.APIKey != "new" || begins != 1 {
		t.Fatal(loaded, err, begins)
	}
	if _, err := os.Stat(path + ".rotation"); !os.IsNotExist(err) {
		t.Fatal("pending retained after success")
	}
}
