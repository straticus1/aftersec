package integration

import (
	"context"
	"net"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/server/auth"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestStreamEventsFlow(t *testing.T) {
	repos := &repository.Repositories{
		Organizations: repository.NewOrganizationRepository(nil),
		Endpoints:     repository.NewEndpointRepository(nil),
	}

	jwtManager := auth.NewJWTManager("test-secret", time.Minute)

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	s := grpc.NewServer(
		grpc.UnaryInterceptor(jwtManager.GRPCUnaryInterceptor),
		grpc.StreamInterceptor(jwtManager.GRPCStreamInterceptor),
	)
	enterpriseSrv := grpcserver.NewServer(repos)
	grpcapi.RegisterEnterpriseServiceServer(s, enterpriseSrv)

	go func() {
		if err := s.Serve(lis); err != nil {
			panic(err)
		}
	}()
	defer s.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial server: %v", err)
	}
	defer conn.Close()

	client := grpcapi.NewEnterpriseServiceClient(conn)

	// Auth setup
	validToken, err := jwtManager.GenerateToken("test-user", "test-org", "agent")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	md := metadata.Pairs("authorization", "Bearer "+validToken)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Call StreamEvents
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	// Send an event
	err = stream.Send(&grpcapi.ClientEvent{
		TenantId:   "tenant-123",
		HardwareId: "test-hw",
		EventType:  "SYSCALL_VIOLATION",
		Timestamp:  time.Now().Unix(),
		Payload:    `{"process": "curl", "syscall": "execve"}`,
	})
	if err != nil {
		t.Fatalf("Failed to send event: %v", err)
	}

	// Close stream and receive ack
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("Failed to receive ack: %v", err)
	}
	if ack.EventsProcessed != 1 {
		t.Fatalf("Expected 1 event processed, got %d", ack.EventsProcessed)
	}
}
