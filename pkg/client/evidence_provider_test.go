package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"aftersec/pkg/attestation"
)

func TestDevelopmentEvidenceProviderProducesVerifiableBoundQuote(t *testing.T) {
	attestationPublic, attestationPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewDevelopmentEvidenceProvider("development", "darwin", attestationPrivate)
	if err != nil {
		t.Fatal(err)
	}
	nonce := sha256.Sum256([]byte("one-time-code"))
	evidence, err := provider.Evidence(context.Background(), "hw-1", nonce[:])
	if err != nil {
		t.Fatal(err)
	}
	verifier := attestation.NewSignedQuoteVerifier(map[string]ed25519.PublicKey{"darwin": attestationPublic})
	if err := verifier.Verify(context.Background(), evidence); err != nil {
		t.Fatalf("development evidence did not verify: %v", err)
	}
}

func TestDevelopmentEvidenceProviderRejectsProductionMode(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDevelopmentEvidenceProvider("production", "linux", privateKey); err == nil {
		t.Fatal("software evidence provider accepted production mode")
	}
}

func TestBuildAttestedEnrollRequestPopulatesCodeBoundEvidence(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewDevelopmentEvidenceProvider("development", "linux", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildAttestedEnrollRequest(context.Background(), provider, EnrollmentDetails{
		OrganizationID: "org-1", EnrollmentCode: "code-1", HardwareID: "hw-1",
		Hostname: "host-1", OSVersion: "linux", AgentVersion: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantNonce := sha256.Sum256([]byte("code-1"))
	if request.OrganizationId != "org-1" || request.EnrollmentCode != "code-1" || request.Platform != "linux" {
		t.Fatalf("missing enrollment fields: %#v", request)
	}
	if string(request.AttestationNonce) != string(wantNonce[:]) || len(request.AttestationQuote) != ed25519.SignatureSize || len(request.PublicKey) == 0 {
		t.Fatalf("invalid request evidence: %#v", request)
	}
}
