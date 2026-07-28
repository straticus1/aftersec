package netsensor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSink(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "network-events.jsonl")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestJSONLBackendRejectsUnsafeSinkPermissions(t *testing.T) {
	path := writeSink(t, "", 0o666)
	if _, err := NewJSONLBackend(path); err == nil {
		t.Fatal("expected writable event sink to be rejected")
	}
}

func TestJSONLBackendEmitsAttributedFlow(t *testing.T) {
	path := writeSink(t, `{"kind":"network_flow","pid":42,"process":"curl","uid":501,"localAddress":"10.0.0.2","localPort":51000,"remoteAddress":"203.0.113.8","remotePort":53,"protocolName":"udp","bytesSent":12,"bytesReceived":34,"startedTimestamp":97,"timestamp":100}`+"\n", 0o600)
	backend, err := NewJSONLBackend(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var got Flow
	err = backend.Run(ctx, func(flow Flow) error {
		got = flow
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want cancellation", err)
	}
	if got.ProcessID != 42 || got.RemotePort != 53 || got.Protocol != "udp" ||
		got.BytesSent != 12 || got.BytesReceived != 34 ||
		got.EndedAt.Sub(got.StartedAt) != 3*time.Second ||
		got.Attribution != AttributionExact {
		t.Fatalf("unexpected flow: %+v", got)
	}
}

func TestJSONLBackendRejectsUnattributedProviderRecord(t *testing.T) {
	path := writeSink(t, `{"kind":"network_flow","pid":0,"process":"","localAddress":"10.0.0.2","localPort":51000,"remoteAddress":"203.0.113.8","remotePort":443,"protocolName":"tcp","timestamp":100}`+"\n", 0o600)
	backend, err := NewJSONLBackend(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sensor := New(backend, true)
	if err := sensor.Run(ctx, make(chan Flow, 1)); !errors.Is(err, ErrMissingAttribution) {
		t.Fatalf("Run() error = %v, want missing attribution", err)
	}
}
