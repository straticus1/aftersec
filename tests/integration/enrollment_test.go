package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/attestation"
	clientpkg "aftersec/pkg/client"
	"aftersec/pkg/server/auth"
	grpcserver "aftersec/pkg/server/grpc"
	"aftersec/pkg/server/repository"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func TestClientEnrollmentFlow(t *testing.T) {
	// Setup generic repository; enrollment dependencies are injected below.
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
	quotePublic, quotePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attestation key: %v", err)
	}
	issuer, caPEM, err := attestation.NewDevelopmentIssuer(time.Now, 15*time.Minute)
	if err != nil {
		t.Fatalf("create development issuer: %v", err)
	}
	enrollment := attestation.NewEnrollmentService(
		attestation.NewMemoryCodeStore(),
		attestation.NewSignedQuoteVerifier(map[string]ed25519.PublicKey{"darwin": quotePublic}),
		issuer,
		time.Now,
	)
	enterpriseSrv.SetEnrollmentService(enrollment, 15*time.Minute)
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

	rpc := grpcapi.NewEnterpriseServiceClient(conn)

	code, err := enrollment.MintCode(context.Background(), "test-org", time.Minute)
	if err != nil {
		t.Fatalf("mint enrollment code: %v", err)
	}
	provider, err := clientpkg.NewDevelopmentEvidenceProvider("development", "darwin", quotePrivate)
	if err != nil {
		t.Fatalf("create evidence provider: %v", err)
	}
	details := clientpkg.EnrollmentDetails{
		OrganizationID: "test-org", EnrollmentCode: code,
		HardwareID: "test-hw-id", Hostname: "test-hostname", OSVersion: "14.2", AgentVersion: "test",
	}
	store := clientpkg.NewFileCredentialStore(t.TempDir(), "development")
	enrollRes, err := clientpkg.RunAttestedEnrollment(context.Background(), rpc, provider, store, caPEM, details, time.Now())
	if err != nil {
		t.Fatalf("Enroll failed: %v", err)
	}
	if !enrollRes.Success {
		t.Fatalf("Expected enrollment success, got false")
	}
	if enrollRes.AccessToken == "" {
		t.Fatalf("Expected access token, got empty")
	}

	if _, err := clientpkg.RunAttestedEnrollment(context.Background(), rpc, provider, store, caPEM, details, time.Now()); err == nil {
		t.Fatal("expected enrollment code replay to be rejected")
	}

	// Generate a valid JWT for subsequent requests
	validToken, err := jwtManager.GenerateToken("test-user", "test-org", "agent")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// 2. Test Heartbeat (Requires Auth)
	md := metadata.Pairs("authorization", "Bearer "+validToken)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	hbRes, err := rpc.Heartbeat(ctx, &grpcapi.HeartbeatRequest{
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
