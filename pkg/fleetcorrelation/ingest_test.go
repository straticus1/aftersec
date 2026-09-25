package fleetcorrelation

import (
	"strings"
	"testing"
	"time"
)

func TestFromTelemetryIgnoresOrdinaryEventsAndRejectsBadHashes(t *testing.T) {
	at := time.Date(2026, 9, 25, 1, 2, 3, 0, time.UTC)
	if _, ok, err := FromTelemetry("t", "e", "exec", `{"path":"/bin/ls"}`, at); err != nil || ok {
		t.Fatalf("ordinary: %v %v", err, ok)
	}
	hash := strings.Repeat("ab", 32)
	event, ok, err := FromTelemetry("t", "host", "allow", `{"path":"/bin/ls","identity":{"SHA256":"`+hash+`"}}`, at)
	if err != nil || !ok || event.Kind != FileHash || event.Value != hash || event.EndpointID != "host" {
		t.Fatalf("%v %v %+v", err, ok, event)
	}
	if _, _, err := FromTelemetry("t", "host", "allow", `{"path":"/bin/ls","identity":{"SHA256":"abcd"}}`, at); err != ErrInvalidEvent {
		t.Fatalf("short hash: %v", err)
	}
	if _, _, err := FromTelemetry("t", "host", "file_hash", `{"id":"1","kind":"credential_use","value":"secret"}`, at); err != ErrInvalidEvent {
		t.Fatalf("raw secret: %v", err)
	}
	login, ok, err := FromTelemetry("t", "host", "ssh_login", `{"id":"login-1","kind":"ssh_login","value":"alice@10.0.0.2"}`, at)
	if err != nil || !ok || login.Kind != SSHLogin {
		t.Fatalf("%v %v %+v", err, ok, login)
	}
}
