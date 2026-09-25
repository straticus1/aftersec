package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBuildReportKeepsPostureAndRejectsAFutureBoot(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	facts := []byte(`{"os_version":"Windows 11 23H2 22631","last_boot":"2026-09-25T11:00:00Z"}`)
	checks := []check{{Name: "Defender real-time protection", Passed: true}, {Name: "Windows Firewall profiles", Passed: false, Error: "disabled"}}
	body, err := buildReport("ENG-01", "11111111-1111-1111-1111-111111111111", "one-time-code", facts, checks, now)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, `"hostname":"ENG-01"`) || !strings.Contains(text, `"passed":false`) || strings.Contains(text, "enrollment_status") {
		t.Fatal(text)
	}
	if _, err = buildReport("ENG-01", "org", "code", []byte(`{"os_version":"Windows 11","last_boot":"2026-09-25T12:05:00Z"}`), checks, now); err == nil {
		t.Fatal("future boot accepted")
	}
	if _, err = buildReport("bad\nhost", "org", "code", facts, checks, now); err == nil {
		t.Fatal("newline hostname accepted")
	}
}

func TestPostInventoryRefusesHTTPAndPostsOverTLS13(t *testing.T) {
	if err := postInventory(context.Background(), "http://mgmt.example:8080", []byte("ca"), []byte("{}")); err == nil {
		t.Fatal("http origin accepted")
	}
	var sawPath string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	srv.StartTLS()
	defer srv.Close()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := postInventory(context.Background(), srv.URL, ca, []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if sawPath != "/api/v1/inventory/windows" {
		t.Fatal(sawPath)
	}
	if err := postInventory(context.Background(), srv.URL, []byte("not a ca"), []byte(`{}`)); err == nil {
		t.Fatal("bad CA accepted")
	}
}
