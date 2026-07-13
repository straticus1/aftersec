package grpcserver

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"sync"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/attestation"
	"aftersec/pkg/eventjournal"
	"aftersec/pkg/server/repository"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type Server struct {
	grpcapi.UnimplementedEnterpriseServiceServer
	repos            *repository.Repositories
	enrollment       *attestation.EnrollmentService
	certificateTTL   time.Duration
	eventJournal     *eventjournal.Journal
	eventQueue       chan *grpcapi.ClientEvent
	mu               sync.RWMutex
	activeStreams    map[string]chan *grpcapi.ServerCommand
	pendingSigmaRule string
}

func (s *Server) SetEnrollmentService(service *attestation.EnrollmentService, certificateTTL time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enrollment = service
	s.certificateTTL = certificateTTL
}

func (s *Server) SetPendingSigmaRule(rule string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pendingSigmaRule = rule
}

func (s *Server) GetPendingSigmaRule() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pendingSigmaRule
}

func NewServer(repos *repository.Repositories) *Server {
	s := &Server{
		repos:         repos,
		eventQueue:    make(chan *grpcapi.ClientEvent, 10000), // High capacity ring-buffer
		activeStreams: make(map[string]chan *grpcapi.ServerCommand),
	}
	// Start the ML Evaluator consumer
	go s.processMLBaselines()
	return s
}

// NewDurableServer opens and verifies a persistent event journal before
// accepting traffic. Startup fails closed if the journal is unavailable or its
// hash chain has been altered.
func NewDurableServer(repos *repository.Repositories, journalPath string, maxJournalBytes int64) (*Server, error) {
	journal, err := eventjournal.Open(journalPath, maxJournalBytes)
	if err != nil {
		return nil, fmt.Errorf("open server event journal: %w", err)
	}
	s := NewServer(repos)
	s.eventJournal = journal
	return s, nil
}

func (s *Server) Close() error {
	if s.eventJournal == nil {
		return nil
	}
	return s.eventJournal.Close()
}

// DispatchCommand sends a command to a connected endpoint's active gRPC stream.
// Returns an error if the endpoint has no active stream or the channel is full.
func (s *Server) DispatchCommand(endpointID string, cmd *grpcapi.ServerCommand) error {
	s.mu.RLock()
	ch, ok := s.activeStreams[endpointID]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("endpoint %q has no active command stream", endpointID)
	}

	select {
	case ch <- cmd:
		return nil
	default:
		return fmt.Errorf("command channel for endpoint %q is full", endpointID)
	}
}

func (s *Server) processMLBaselines() {
	for event := range s.eventQueue {
		// Stub: pipe into ML evaluation engine for UEBA tracking
		// Evaluated threats would trigger immediate Heartbeat action overrides
		_ = event
	}
}

// Threats: Enroll rejects anonymous, unprovisioned, replayed, or unattested
// endpoints and returns credentials only after the configured trust service
// succeeds. It does not select trust roots; startup configuration owns that.
func (s *Server) Enroll(ctx context.Context, req *grpcapi.EnrollRequest) (*grpcapi.EnrollResponse, error) {
	if req == nil || req.HardwareId == "" {
		return nil, status.Error(codes.InvalidArgument, "missing hardware_id")
	}
	s.mu.RLock()
	service := s.enrollment
	certificateTTL := s.certificateTTL
	s.mu.RUnlock()
	if service == nil || certificateTTL <= 0 {
		return nil, status.Error(codes.FailedPrecondition, "attested enrollment is not configured")
	}
	result, err := service.Enroll(ctx, req.EnrollmentCode, attestation.Request{
		OrganizationID: req.OrganizationId,
		HardwareID:     req.HardwareId,
		Hostname:       req.Hostname,
		Evidence: attestation.Evidence{
			HardwareID: req.HardwareId,
			Platform:   req.Platform,
			Nonce:      req.AttestationNonce,
			Quote:      req.AttestationQuote,
			PublicKey:  req.PublicKey,
		},
	})
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "attested enrollment rejected")
	}
	return &grpcapi.EnrollResponse{
		TenantId:             req.OrganizationId,
		AccessToken:          result.RefreshToken,
		Success:              true,
		Message:              "Successfully enrolled attested endpoint",
		ClientCertificate:    result.ClientCertificate,
		CertificateExpiresAt: time.Now().Add(certificateTTL).Unix(),
	}, nil
}

func (s *Server) Heartbeat(ctx context.Context, req *grpcapi.HeartbeatRequest) (*grpcapi.HeartbeatResponse, error) {
	if req.TenantId == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant_id")
	}

	action := "NONE"
	if rule := s.GetPendingSigmaRule(); rule != "" {
		action = "RUN_SIGMA::" + base64.StdEncoding.EncodeToString([]byte(rule))
	}

	// Stub heartbeat tracking
	return &grpcapi.HeartbeatResponse{
		PolicyUpdated: false,
		NewPolicyHash: "",
		Action:        action,
	}, nil
}

// Threats: StreamEvents never acknowledges telemetry that was not durably
// committed. Deployments configured with a journal survive process loss;
// queue-only development deployments still refuse to acknowledge dropped data.
func (s *Server) StreamEvents(stream grpcapi.EnterpriseService_StreamEventsServer) error {
	var count int32
	for {
		event, err := stream.Recv()
		if err != nil {
			// EOF or client disconnected
			return stream.SendAndClose(&grpcapi.StreamAck{
				EventsProcessed: count,
				Message:         "Stream closed",
			})
		}

		if s.eventJournal != nil {
			payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(event)
			if err != nil {
				return stream.SendAndClose(&grpcapi.StreamAck{
					EventsProcessed: count,
					Message:         "Event encoding failed; retry unacknowledged events",
				})
			}
			if _, err := s.eventJournal.Append(payload); err != nil {
				return stream.SendAndClose(&grpcapi.StreamAck{
					EventsProcessed: count,
					Message:         "Durable event journal unavailable; retry unacknowledged events",
				})
			}
			count++
			select {
			case s.eventQueue <- event:
			default:
				// The event is already durable and can be replayed to processors.
			}
			continue
		}

		// Push the event to the async aggregation queue. If the queue is full,
		// close the stream immediately and acknowledge only events already
		// accepted, allowing the client to retry the unacknowledged remainder.
		select {
		case s.eventQueue <- event:
			count++
		default:
			return stream.SendAndClose(&grpcapi.StreamAck{
				EventsProcessed: count,
				Message:         "Event queue full; retry unacknowledged events",
			})
		}

		// Periodically acknowledge to keep connection alive if needed, but for ClientStreaming we just collect
	}
}

func (s *Server) ConnectCommandStream(stream grpcapi.EnterpriseService_ConnectCommandStreamServer) error {
	// 1. Wait for registration payload
	msg, err := stream.Recv()
	if err != nil {
		return err
	}

	endpointID := msg.HardwareId

	cmdChan := make(chan *grpcapi.ServerCommand, 50)

	s.mu.Lock()
	s.activeStreams[endpointID] = cmdChan
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.activeStreams, endpointID)
		s.mu.Unlock()
	}()

	// 2. Consume responses in the background (Async Receiver)
	errChan := make(chan error, 1)
	go func() {
		for {
			res, err := stream.Recv()
			if err != nil {
				errChan <- err
				return
			}
			// Route command execution output to the Dashboard / Admin Log
			log.Printf("Received Command Output from %s for %s: %s", endpointID, res.CommandId, res.Status)
		}
	}()

	// 3. Push Commands loop
	for {
		select {
		case err := <-errChan:
			return err
		case cmd := <-cmdChan:
			if err := stream.Send(cmd); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}
