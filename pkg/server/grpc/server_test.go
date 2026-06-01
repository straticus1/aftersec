package grpcserver

import (
	"testing"

	grpcapi "aftersec/pkg/api/grpc"
)

func TestDispatchCommand_NoActiveStream(t *testing.T) {
	s := NewServer(nil)
	err := s.DispatchCommand("endpoint-xyz", &grpcapi.ServerCommand{CommandId: "cmd-1", Action: "SCAN"})
	if err == nil {
		t.Fatal("expected error for endpoint with no active stream, got nil")
	}
}

func TestDispatchCommand_Success(t *testing.T) {
	s := NewServer(nil)

	ch := make(chan *grpcapi.ServerCommand, 5)
	s.mu.Lock()
	s.activeStreams["endpoint-abc"] = ch
	s.mu.Unlock()

	cmd := &grpcapi.ServerCommand{CommandId: "cmd-1", Action: "ISOLATE"}
	if err := s.DispatchCommand("endpoint-abc", cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case got := <-ch:
		if got.CommandId != "cmd-1" {
			t.Errorf("expected command ID %q, got %q", "cmd-1", got.CommandId)
		}
		if got.Action != "ISOLATE" {
			t.Errorf("expected action %q, got %q", "ISOLATE", got.Action)
		}
	default:
		t.Error("command not written to channel")
	}
}

func TestDispatchCommand_FullChannel(t *testing.T) {
	s := NewServer(nil)

	ch := make(chan *grpcapi.ServerCommand, 1)
	ch <- &grpcapi.ServerCommand{CommandId: "blocker"} // fill it
	s.mu.Lock()
	s.activeStreams["endpoint-full"] = ch
	s.mu.Unlock()

	err := s.DispatchCommand("endpoint-full", &grpcapi.ServerCommand{CommandId: "cmd-2", Action: "SCAN"})
	if err == nil {
		t.Fatal("expected error when channel is full, got nil")
	}
}

func TestDispatchCommand_ConcurrentStreams(t *testing.T) {
	s := NewServer(nil)

	endpoints := []string{"ep-a", "ep-b", "ep-c"}
	channels := make(map[string]chan *grpcapi.ServerCommand)

	s.mu.Lock()
	for _, id := range endpoints {
		ch := make(chan *grpcapi.ServerCommand, 5)
		channels[id] = ch
		s.activeStreams[id] = ch
	}
	s.mu.Unlock()

	for _, id := range endpoints {
		cmd := &grpcapi.ServerCommand{CommandId: id + "-cmd", Action: "SCAN"}
		if err := s.DispatchCommand(id, cmd); err != nil {
			t.Errorf("dispatch to %q failed: %v", id, err)
		}
	}

	for _, id := range endpoints {
		select {
		case got := <-channels[id]:
			if got.CommandId != id+"-cmd" {
				t.Errorf("endpoint %q: expected command %q, got %q", id, id+"-cmd", got.CommandId)
			}
		default:
			t.Errorf("endpoint %q: no command in channel", id)
		}
	}
}

func TestSetGetPendingSigmaRule(t *testing.T) {
	s := NewServer(nil)
	const rule = "title: Test\ndetection:\n  condition: true"
	s.SetPendingSigmaRule(rule)
	if got := s.GetPendingSigmaRule(); got != rule {
		t.Errorf("expected rule %q, got %q", rule, got)
	}
}

func TestSetPendingSigmaRule_Overwrite(t *testing.T) {
	s := NewServer(nil)
	s.SetPendingSigmaRule("rule-v1")
	s.SetPendingSigmaRule("rule-v2")
	if got := s.GetPendingSigmaRule(); got != "rule-v2" {
		t.Errorf("expected %q after overwrite, got %q", "rule-v2", got)
	}
}

func TestHeartbeat_EmptyTenantIDReturnsError(t *testing.T) {
	s := NewServer(nil)
	_, err := s.Heartbeat(nil, &grpcapi.HeartbeatRequest{TenantId: ""})
	if err == nil {
		t.Fatal("expected error for empty tenant_id, got nil")
	}
}

func TestHeartbeat_WithPendingSigmaRule(t *testing.T) {
	s := NewServer(nil)
	s.SetPendingSigmaRule("detection: condition: true")

	resp, err := s.Heartbeat(nil, &grpcapi.HeartbeatRequest{TenantId: "tenant-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Action == "" || resp.Action == "NONE" {
		t.Errorf("expected action to encode sigma rule, got %q", resp.Action)
	}
}
