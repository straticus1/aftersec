package grpcserver

// Threats: these tests exercise the fail-closed / data-retention invariants of
// the enterprise gRPC control plane.
//   - Endpoint command dispatch must never silently drop a command: on a full
//     or absent channel the caller MUST get an error so it can retry, and any
//     command already queued must remain intact.
//   - Client event ingestion (StreamEvents) must not acknowledge events it
//     silently discarded — an over-reported StreamAck is a data-loss defect
//     (an operator believes telemetry was ingested when it was dropped).
//   - Enrollment must fail closed on an unidentified/empty request rather than
//     handing out a static access token.
// What they do NOT cover: transport-level auth (mTLS), replay, or authz of the
// dispatched action itself.

import (
	"context"
	"crypto/sha256"
	"io"
	"path/filepath"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/attestation"
	"aftersec/pkg/eventjournal"
	"google.golang.org/grpc"
)

type acceptAttestation struct{}

func (acceptAttestation) Verify(context.Context, attestation.Evidence) error { return nil }

type testCertificateIssuer struct{}

func (testCertificateIssuer) IssueClientCertificate(context.Context, attestation.VerifiedIdentity) ([]byte, error) {
	return []byte("client-certificate"), nil
}

// --- Area 1: command dispatch is fail-closed and does not lose queued data ---

// TestDispatchCommand_FullChannel_SurfacesErrorAndPreservesQueued proves the
// real DispatchCommand fix (commit 296ae14): when the endpoint's command
// channel is full the call returns an error (so the caller can retry) and the
// command already sitting in the channel is neither corrupted nor evicted.
func TestDispatchCommand_FullChannel_SurfacesErrorAndPreservesQueued(t *testing.T) {
	s := NewServer(nil)

	ch := make(chan *grpcapi.ServerCommand, 1)
	existing := &grpcapi.ServerCommand{CommandId: "already-queued", Action: "ISOLATE"}
	ch <- existing // fill the single slot

	s.mu.Lock()
	s.activeStreams["ep-full"] = ch
	s.mu.Unlock()

	err := s.DispatchCommand("ep-full", &grpcapi.ServerCommand{CommandId: "new-cmd", Action: "SCAN"})
	if err == nil {
		t.Fatal("expected error when command channel is full, got nil (command would be silently dropped)")
	}

	// The previously queued command must still be intact and deliverable.
	select {
	case got := <-ch:
		if got.CommandId != "already-queued" {
			t.Errorf("queued command was corrupted: got CommandId %q, want %q", got.CommandId, "already-queued")
		}
	default:
		t.Fatal("previously queued command was lost when the channel reported full")
	}
}

// TestDispatchCommand_OfflineEndpoint_FailsClosed proves an offline endpoint
// (no active stream) surfaces an error rather than pretending the command was
// delivered.
func TestDispatchCommand_OfflineEndpoint_FailsClosed(t *testing.T) {
	s := NewServer(nil)
	if err := s.DispatchCommand("never-connected", &grpcapi.ServerCommand{CommandId: "c", Action: "SCAN"}); err == nil {
		t.Fatal("expected error dispatching to an endpoint with no active stream, got nil")
	}
}

// --- Area 1: client event ingestion must not over-ack silently dropped data ---

// mockStreamEventsServer is a minimal ClientStreamingServer used to drive
// Server.StreamEvents deterministically. Only Recv and SendAndClose are
// exercised by the handler; the embedded ServerStream is left nil.
type mockStreamEventsServer struct {
	grpc.ServerStream
	events []*grpcapi.ClientEvent
	idx    int
	ack    *grpcapi.StreamAck
}

func (m *mockStreamEventsServer) Recv() (*grpcapi.ClientEvent, error) {
	if m.idx >= len(m.events) {
		return nil, io.EOF
	}
	e := m.events[m.idx]
	m.idx++
	return e, nil
}

func (m *mockStreamEventsServer) SendAndClose(ack *grpcapi.StreamAck) error {
	m.ack = ack
	return nil
}

// TestStreamEvents_DoesNotAckDroppedEvents feeds more events than the ingest
// queue can hold. StreamEvents (server.go:116-125) pushes to the queue with a
// non-blocking select whose default branch SILENTLY DROPS the event, yet still
// increments the count returned in StreamAck. The security invariant is that
// the server must not acknowledge (EventsProcessed) events it discarded —
// otherwise upstream believes telemetry was ingested when it was lost.
//
// This test is expected to FAIL against the current code, documenting the
// data-loss defect at pkg/server/grpc/server.go:116-125. It is left failing
// intentionally per the task contract (do not paper over a fail-open/loss path).
func TestStreamEvents_DoesNotAckDroppedEvents(t *testing.T) {
	// Construct the Server directly (no NewServer) so the processMLBaselines
	// drainer goroutine is NOT running and queue occupancy is deterministic.
	s := &Server{
		eventQueue:    make(chan *grpcapi.ClientEvent, 1), // room for exactly one
		activeStreams: make(map[string]chan *grpcapi.ServerCommand),
	}

	fed := []*grpcapi.ClientEvent{
		{HardwareId: "hw-1", EventType: "SYSCALL"},
		{HardwareId: "hw-1", EventType: "FILE_MOD"},
		{HardwareId: "hw-1", EventType: "NETWORK_CONN"},
	}
	stream := &mockStreamEventsServer{events: fed}

	if err := s.StreamEvents(stream); err != nil {
		t.Fatalf("StreamEvents returned error: %v", err)
	}
	if stream.ack == nil {
		t.Fatal("StreamEvents did not send a StreamAck")
	}

	// Count what was actually retained (durably enqueued) vs. what was acked.
	close(s.eventQueue)
	retained := 0
	for range s.eventQueue {
		retained++
	}

	if int(stream.ack.EventsProcessed) != retained {
		t.Fatalf("DATA LOSS: StreamAck reported %d events processed but only %d were retained; %d silently dropped (server.go:116-125)",
			stream.ack.EventsProcessed, retained, int(stream.ack.EventsProcessed)-retained)
	}
}

func TestStreamEvents_AcknowledgesOnlyDurablyJournaledEvents(t *testing.T) {
	journal, err := eventjournal.Open(filepath.Join(t.TempDir(), "server-events.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	s := &Server{
		eventJournal:  journal,
		activeStreams: make(map[string]chan *grpcapi.ServerCommand),
	}
	stream := &mockStreamEventsServer{events: []*grpcapi.ClientEvent{
		{HardwareId: "hw-1", EventType: "PROCESS_EXEC", Payload: `{"path":"/bin/sh"}`},
		{HardwareId: "hw-1", EventType: "NETWORK_CONN", Payload: `{"remote":"192.0.2.1"}`},
	}}

	if err := s.StreamEvents(stream); err != nil {
		t.Fatal(err)
	}
	if stream.ack == nil || stream.ack.EventsProcessed != 2 {
		t.Fatalf("ack = %#v, want two durably committed events", stream.ack)
	}
	records, err := journal.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("journal contains %d records, want 2", len(records))
	}
}

func TestStreamEvents_JournalFullDoesNotAcknowledgeEvent(t *testing.T) {
	journal, err := eventjournal.Open(filepath.Join(t.TempDir(), "server-events.db"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	s := &Server{
		eventJournal:  journal,
		activeStreams: make(map[string]chan *grpcapi.ServerCommand),
	}
	stream := &mockStreamEventsServer{events: []*grpcapi.ClientEvent{{HardwareId: "hw-1", EventType: "PROCESS_EXEC"}}}

	if err := s.StreamEvents(stream); err != nil {
		t.Fatal(err)
	}
	if stream.ack == nil || stream.ack.EventsProcessed != 0 {
		t.Fatalf("ack = %#v, want zero events after journal failure", stream.ack)
	}
	records, err := journal.Pending(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("journal retained %d partial records", len(records))
	}
}

// --- Area 2: enrollment must fail closed on an unidentified request ---

// TestEnroll_RejectsUnidentifiedRequest proves that an enrollment request with
// no hardware identity is rejected. The current handler (server.go:75-83)
// ignores the request entirely and unconditionally returns Success=true with a
// hardcoded, predictable AccessToken ("stubbing_token_123") — a fail-open stub
// that would enroll any caller and issue a static credential.
//
// Expected to FAIL against current code, documenting the fail-open enrollment
// stub at pkg/server/grpc/server.go:75-83. Left failing intentionally.
func TestEnroll_RejectsUnidentifiedRequest(t *testing.T) {
	s := NewServer(nil)

	resp, err := s.Enroll(nil, &grpcapi.EnrollRequest{}) // no HardwareId / Hostname
	if err != nil {
		return // rejected with an error: fail-closed, acceptable
	}
	if resp == nil {
		return
	}
	if resp.Success && resp.AccessToken != "" {
		t.Fatalf("FAIL-OPEN: Enroll issued AccessToken=%q for an unidentified request (server.go:75-83)", resp.AccessToken)
	}
}

// TestEnroll_DoesNotIssueStaticToken proves the access token is not a hardcoded
// constant. Even for an otherwise-valid enrollment, a predictable static token
// violates rule 1 (CSPRNG for tokens). Expected to FAIL against current code.
func TestEnroll_DoesNotIssueStaticToken(t *testing.T) {
	s := NewServer(nil)

	valid := &grpcapi.EnrollRequest{HardwareId: "hw-abc", Hostname: "host-1", OsVersion: "14.5", AgentVersion: "1.0.0"}
	r1, err1 := s.Enroll(nil, valid)
	r2, err2 := s.Enroll(nil, valid)
	if err1 != nil || err2 != nil {
		return // rejecting is fail-closed; acceptable
	}
	if r1 == nil || r2 == nil {
		return
	}
	if r1.AccessToken != "" && r1.AccessToken == r2.AccessToken {
		t.Fatalf("STATIC TOKEN: Enroll returned identical access tokens across enrollments (%q); token is not CSPRNG-derived (server.go:75-83)", r1.AccessToken)
	}
}

func TestEnroll_UsesAttestationServiceAndReturnsClientCertificate(t *testing.T) {
	now := time.Unix(1000, 0)
	service := attestation.NewEnrollmentService(
		attestation.NewMemoryCodeStore(), acceptAttestation{}, testCertificateIssuer{}, func() time.Time { return now },
	)
	code, err := service.MintCode(context.Background(), "org-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil)
	s.SetEnrollmentService(service, 15*time.Minute)
	nonce := sha256.Sum256([]byte(code))
	resp, err := s.Enroll(context.Background(), &grpcapi.EnrollRequest{
		OrganizationId:   "org-1",
		EnrollmentCode:   code,
		HardwareId:       "hw-1",
		Hostname:         "host-1",
		Platform:         "darwin",
		AttestationNonce: nonce[:],
		AttestationQuote: []byte("quote"),
		PublicKey:        []byte("public-key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TenantId != "org-1" || resp.AccessToken == "" || string(resp.ClientCertificate) != "client-certificate" {
		t.Fatalf("unexpected enrollment response: %#v", resp)
	}
	if resp.CertificateExpiresAt <= time.Now().Unix() {
		t.Fatalf("certificate expiry is not in the future: %d", resp.CertificateExpiresAt)
	}
}

func TestEnroll_FailsClosedWithoutConfiguredAttestationService(t *testing.T) {
	s := NewServer(nil)
	_, err := s.Enroll(context.Background(), &grpcapi.EnrollRequest{HardwareId: "hw-1"})
	if err == nil {
		t.Fatal("enrollment succeeded without configured attestation service")
	}
}
