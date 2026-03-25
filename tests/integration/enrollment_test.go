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

func TestClientEnrollmentFlow(t *testing.T) {
	// Setup generic repository (with nil DB for stubbed endpoints)
	repos := &repository.Repositories{
		Organizations: repository.NewOrganizationRepository(nil),
		Endpoints:     repository.NewEndpointRepository(nil),
	}

	jwtManager := auth.NewJWTManager("test-secret", time.Minute)

	// Setup gRPC Server
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

	// Setup gRPC Client
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial server: %v", err)
	}
	defer conn.Close()

	client := grpcapi.NewEnterpriseServiceClient(conn)

	// 1. Test Enrollment (No Auth Required for Enrollment per our rules)
	enrollRes, err := client.Enroll(context.Background(), &grpcapi.EnrollRequest{
		HardwareId:      "test-hw-id",
		Hostname:        "test-hostname",
		OsVersion:       "14.2",
	})
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if !enrollRes.Success {
		t.Fatalf("Expected enrollment success, got false")
	}
	if enrollRes.AccessToken == "" {
		t.Fatalf("Expected access token, got empty")
	}

	t.Logf("Successfully enrolled! Token: %s", enrollRes.AccessToken)

	// Generate a valid JWT for subsequent requests
	validToken, err := jwtManager.GenerateToken("test-user", "test-org", "agent")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 2. Test Heartbeat (Requires Auth)
	md := metadata.Pairs("authorization", "Bearer "+validToken)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	hbRes, err := client.Heartbeat(ctx, &grpcapi.HeartbeatRequest{
		TenantId:   "tenant-12345",
		HardwareId: "test-hw-id",
		Timestamp:  time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
	if hbRes.Action != "NONE" {
		t.Fatalf("Expected NONE action, got %s", hbRes.Action)
	}
}
