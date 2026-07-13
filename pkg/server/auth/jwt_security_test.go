package auth

// Threats: only the exact enrollment RPC is public; similarly named RPC paths
// must not bypass authentication. Enrollment identity checks remain handler-side.

import (
	"context"
	"testing"
	"time"
)

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
