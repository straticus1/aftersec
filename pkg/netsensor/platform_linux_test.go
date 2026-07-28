//go:build linux

package netsensor

import (
	"testing"
	"time"
)

func TestLinuxUDPEventPreservesCountersAndDuration(t *testing.T) {
	event := linuxFlowEvent{
		TimestampNS:   9_000_000_000,
		StartedNS:     6_000_000_000,
		BytesSent:     512,
		BytesReceived: 1024,
		PID:           42,
		UID:           1000,
		LocalPort:     53000,
		RemotePort:    53,
		Family:        2,
		Protocol:      17,
	}
	copy(event.Process[:], "resolver")
	copy(event.LocalAddr[:], []byte{10, 0, 0, 2})
	copy(event.RemoteAddr[:], []byte{1, 1, 1, 1})
	flow, err := event.flow()
	if err != nil {
		t.Fatal(err)
	}
	if flow.Protocol != "udp" || flow.BytesSent != 512 || flow.BytesReceived != 1024 {
		t.Fatalf("flow=%+v", flow)
	}
	if flow.EndedAt.Sub(flow.StartedAt) != 3*time.Second {
		t.Fatalf("duration=%v", flow.EndedAt.Sub(flow.StartedAt))
	}
}
