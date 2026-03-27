package grpcserver

import (
	"context"
	"encoding/base64"
	"log"
	"sync"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/server/repository"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	grpcapi.UnimplementedEnterpriseServiceServer
	repos         *repository.Repositories
	eventQueue       chan *grpcapi.ClientEvent
	mu               sync.RWMutex
	activeStreams    map[string]chan *grpcapi.ServerCommand
	pendingSigmaRule string
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

func (s *Server) processMLBaselines() {
	for event := range s.eventQueue {
		// Stub: pipe into ML evaluation engine for UEBA tracking
		// Evaluated threats would trigger immediate Heartbeat action overrides
		_ = event
	}
}

func (s *Server) Enroll(ctx context.Context, req *grpcapi.EnrollRequest) (*grpcapi.EnrollResponse, error) {
	// Stub enrollment logic
	return &grpcapi.EnrollResponse{
		TenantId:    "tenant-12345",
		AccessToken: "stubbing_token_123",
		Success:     true,
		Message:     "Successfully enrolled endpoint",
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

		// Push event to an async Aggregation Queue (Redis/Kafka) for ML UEBA Evaluation
		select {
		case s.eventQueue <- event:
		default:
			// Queue is full, drop event to prevent backpressure blocking
		}
		count++

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
