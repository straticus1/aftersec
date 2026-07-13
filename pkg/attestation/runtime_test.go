package attestation

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestBuildRuntimeProductionRequiresAllTrustMaterial(t *testing.T) {
	_, err := BuildRuntime(RuntimeConfig{Mode: "production", CertificateLifetime: time.Hour}, (*sql.DB)(nil), nil)
	if err == nil {
		t.Fatal("production enrollment runtime accepted missing database and trust material")
	}
}

func TestBuildRuntimeDoesNotImplicitlySelectDevelopmentMode(t *testing.T) {
	_, err := BuildRuntime(RuntimeConfig{CertificateLifetime: time.Hour}, nil, nil)
	if err == nil {
		t.Fatal("empty mode implicitly enabled development enrollment")
	}
}

func TestBuildRuntimeDevelopmentCreatesInMemoryIssuerOnlyWhenExplicit(t *testing.T) {
	runtime, err := BuildRuntime(RuntimeConfig{
		Mode:                "development",
		CertificateLifetime: 15 * time.Minute,
	}, nil, acceptAllVerifier{})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.Service == nil || len(runtime.DevelopmentCAPEM) == 0 {
		t.Fatal("explicit development mode did not create enrollment runtime and CA")
	}
}

type acceptAllVerifier struct{}

func (acceptAllVerifier) Verify(_ context.Context, _ Evidence) error { return nil }
