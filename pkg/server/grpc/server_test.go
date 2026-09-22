package grpcserver

import (
	"context"
	"crypto/ed25519"
	"strings"
	"sync"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/detection"
	"aftersec/pkg/selfprotect"
	"aftersec/pkg/server/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type silenceStore struct {
	mu        sync.Mutex
	incidents []selfprotect.Incident
	err       error
}

func (s *silenceStore) RecordSilence(incident selfprotect.Incident) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.incidents = append(s.incidents, incident)
	return nil
}

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

func testSigmaPack(t *testing.T, version uint64) (ed25519.PublicKey, detection.SignedPack) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := detection.SignPack(detection.Pack{Version: version, Rules: []detection.Rule{{ID: "tmp", YAML: "title: tmp\ndetection:\n  selection:\n    Image: /tmp/a\n"}}}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return pub, pack
}

func TestQueueSigmaPackRejectsUnsignedAndRollback(t *testing.T) {
	s := NewServer(nil)
	pub, pack := testSigmaPack(t, 2)
	s.SetSigmaStore(detection.NewStore(pub))
	if err := s.QueueSigmaPack(pack, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, ok := s.PendingSigmaPack()
	if !ok || got.Pack.Version != 2 {
		t.Fatalf("%+v %v", got, ok)
	}
	tampered := pack
	tampered.Signature[0] ^= 1
	if err := s.QueueSigmaPack(tampered, time.Now()); err == nil {
		t.Fatal("accepted tampered pack")
	}
	if err := NewServer(nil).QueueSigmaPack(pack, time.Now()); err == nil {
		t.Fatal("queued pack without a key store")
	}
}

func TestHeartbeat_EmptyTenantIDReturnsError(t *testing.T) {
	s := NewServer(nil)
	_, err := s.Heartbeat(nil, &grpcapi.HeartbeatRequest{TenantId: ""})
	if err == nil {
		t.Fatal("expected error for empty tenant_id, got nil")
	}
}

func TestHeartbeat_WithPendingSigmaPack(t *testing.T) {
	s := NewServer(nil)
	pub, pack := testSigmaPack(t, 2)
	s.SetSigmaStore(detection.NewStore(pub))
	if err := s.QueueSigmaPack(pack, time.Now()); err != nil {
		t.Fatal(err)
	}

	resp, err := s.Heartbeat(nil, &grpcapi.HeartbeatRequest{
		TenantId: "tenant-1", HardwareId: "endpoint-1", Timestamp: time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(resp.Action, detection.HeartbeatPrefix) {
		t.Errorf("expected signed pack action, got %q", resp.Action)
	}
}

func TestHeartbeat_RecordsSilenceIncidentAfterDeadline(t *testing.T) {
	store := &silenceStore{}
	s := NewServer(nil)
	s.SetHeartbeatTracker(selfprotect.NewTracker(5*time.Minute, 2*time.Minute, store))
	heartbeatAt := time.Now().Truncate(time.Second)

	_, err := s.Heartbeat(nil, &grpcapi.HeartbeatRequest{
		TenantId: "tenant-1", HardwareId: "endpoint-1", Timestamp: heartbeatAt.Unix(),
	})
	if err != nil {
		t.Fatalf("heartbeat failed: %v", err)
	}
	if err := s.CheckHeartbeatSilence(heartbeatAt.Add(6 * time.Minute)); err != nil {
		t.Fatalf("silence check failed: %v", err)
	}
	if len(store.incidents) != 1 || store.incidents[0].HardwareID != "endpoint-1" {
		t.Fatalf("expected one endpoint silence incident, got %+v", store.incidents)
	}
}

func TestHeartbeat_RejectsClockSkewInsteadOfResettingSilence(t *testing.T) {
	store := &silenceStore{}
	s := NewServer(nil)
	s.SetHeartbeatTracker(selfprotect.NewTracker(5*time.Minute, time.Minute, store))

	_, err := s.Heartbeat(nil, &grpcapi.HeartbeatRequest{
		TenantId: "tenant-1", HardwareId: "endpoint-1", Timestamp: time.Now().Add(-10 * time.Minute).Unix(),
	})
	if err == nil {
		t.Fatal("expected skewed heartbeat to be rejected")
	}
}

func TestHeartbeat_RejectsTenantDifferentFromAuthenticatedOrganization(t *testing.T) {
	manager := auth.NewJWTManager("test-secret", time.Minute)
	token, err := manager.GenerateToken("operator", "org-authenticated", "security_operator")
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	s := NewServer(nil)
	_, err = manager.GRPCUnaryInterceptor(
		ctx,
		&grpcapi.HeartbeatRequest{TenantId: "org-other", HardwareId: "endpoint-1", Timestamp: time.Now().Unix()},
		&grpc.UnaryServerInfo{FullMethod: "/aftersec.api.EnterpriseService/Heartbeat"},
		func(handlerCtx context.Context, request interface{}) (interface{}, error) {
			return s.Heartbeat(handlerCtx, request.(*grpcapi.HeartbeatRequest))
		},
	)
	if err == nil {
		t.Fatal("cross-tenant heartbeat was accepted")
	}
}
