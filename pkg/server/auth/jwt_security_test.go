package auth

// Threats: only the exact enrollment RPC is public; similarly named RPC paths
// must not bypass authentication. Enrollment identity checks remain handler-side.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestHTTPMiddlewarePropagatesValidatedClaims(t *testing.T) {
	m := NewJWTManager("test-secret", time.Minute)
	token, err := m.GenerateToken("operator", "org-1", "security_operator")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := m.HTTPMiddleware(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.UserID != "operator" || claims.OrganizationID != "org-1" || claims.Role != "security_operator" {
			t.Fatalf("claims = %+v, ok=%v", claims, ok)
		}
		called = true
	})
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("protected handler was not called")
	}
}

func TestAuthorizeGRPC_ExemptsExactGeneratedEnrollmentMethod(t *testing.T) {
	m := NewJWTManager("test-secret", time.Minute)
	if err := m.authorizeGRPC(context.Background(), "/aftersec.api.EnterpriseService/Enroll"); err != nil {
		t.Fatalf("exact enrollment method was not exempt: %v", err)
	}
}

func TestAuthorizeGRPC_DoesNotExemptSimilarEnrollmentPath(t *testing.T) {
	m := NewJWTManager("test-secret", time.Minute)
	if err := m.authorizeGRPC(context.Background(), "/evil.Service/Enroll"); err == nil {
		t.Fatal("similarly named enrollment method bypassed authentication")
	}
}

func TestGRPCUnaryInterceptorPropagatesValidatedClaims(t *testing.T) {
	m := NewJWTManager("test-secret", time.Minute)
	token, err := m.GenerateToken("operator", "org-1", "security_operator")
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	_, err = m.GRPCUnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/aftersec.api.EnterpriseService/Heartbeat"},
		func(handlerCtx context.Context, _ interface{}) (interface{}, error) {
			claims, ok := ClaimsFromContext(handlerCtx)
			if !ok || claims.OrganizationID != "org-1" || claims.Role != "security_operator" {
				t.Fatalf("claims = %+v, ok=%v", claims, ok)
			}
			return nil, nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
