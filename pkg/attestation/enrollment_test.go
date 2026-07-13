package attestation

// Threats: enrollment must reject wrong-org, expired, replayed, or unverifiable
// requests before issuing credentials. Hardware provenance is delegated to the
// platform verifier and tested through its fail-closed contract here.

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func evidenceForCode(hardwareID, code string) Evidence {
	nonce := sha256.Sum256([]byte(code))
	return Evidence{HardwareID: hardwareID, Nonce: nonce[:]}
}

type verifierFunc func(context.Context, Evidence) error

func (f verifierFunc) Verify(ctx context.Context, evidence Evidence) error { return f(ctx, evidence) }

type issuerFunc func(context.Context, VerifiedIdentity) ([]byte, error)

func (f issuerFunc) IssueClientCertificate(ctx context.Context, identity VerifiedIdentity) ([]byte, error) {
	return f(ctx, identity)
}

type atomicCodeStore struct {
	*MemoryCodeStore
	consumeCalled  bool
	finalizeCalled bool
}

func (s *atomicCodeStore) Consume(ctx context.Context, org string, digest [sha256.Size]byte, now time.Time) error {
	s.consumeCalled = true
	return s.MemoryCodeStore.Consume(ctx, org, digest, now)
}

func (s *atomicCodeStore) Finalize(_ context.Context, _ string, _ [sha256.Size]byte, _ time.Time, _ EnrollmentCommit) error {
	s.finalizeCalled = true
	return nil
}

func validService(t *testing.T, now time.Time) (*EnrollmentService, string) {
	t.Helper()
	store := NewMemoryCodeStore()
	service := NewEnrollmentService(store,
		verifierFunc(func(context.Context, Evidence) error { return nil }),
		issuerFunc(func(context.Context, VerifiedIdentity) ([]byte, error) { return []byte("certificate"), nil }),
		func() time.Time { return now },
	)
	code, err := service.MintCode(context.Background(), "org-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return service, code
}

func TestEnrollConsumesCodeAndIssuesUniqueCredentials(t *testing.T) {
	now := time.Unix(1000, 0)
	service, firstCode := validService(t, now)
	secondCode, err := service.MintCode(context.Background(), "org-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{OrganizationID: "org-1", HardwareID: "hw-1", Evidence: evidenceForCode("hw-1", firstCode)}
	first, err := service.Enroll(context.Background(), firstCode, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Evidence = evidenceForCode("hw-1", secondCode)
	second, err := service.Enroll(context.Background(), secondCode, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.RefreshToken == "" || first.RefreshToken == second.RefreshToken {
		t.Fatal("refresh tokens are empty or repeated")
	}
	if string(first.ClientCertificate) != "certificate" {
		t.Fatalf("certificate = %q", first.ClientCertificate)
	}
	request.Evidence = evidenceForCode("hw-1", firstCode)
	if _, err := service.Enroll(context.Background(), firstCode, request); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("replay error = %v, want ErrCodeInvalid", err)
	}
}

func TestEnrollRejectsAttestationFailureWithoutIssuingCertificate(t *testing.T) {
	now := time.Unix(1000, 0)
	issued := false
	service := NewEnrollmentService(NewMemoryCodeStore(),
		verifierFunc(func(context.Context, Evidence) error { return errors.New("bad quote") }),
		issuerFunc(func(context.Context, VerifiedIdentity) ([]byte, error) { issued = true; return nil, nil }),
		func() time.Time { return now },
	)
	code, err := service.MintCode(context.Background(), "org-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Enroll(context.Background(), code, Request{OrganizationID: "org-1", HardwareID: "hw-1", Evidence: evidenceForCode("hw-1", code)})
	if !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("error = %v, want ErrAttestationInvalid", err)
	}
	if issued {
		t.Fatal("certificate was issued after attestation failure")
	}
}

func TestEnrollRejectsExpiredAndWrongOrganizationCodes(t *testing.T) {
	now := time.Unix(1000, 0)
	service, code := validService(t, now)
	service.now = func() time.Time { return now.Add(2 * time.Minute) }
	request := Request{OrganizationID: "org-1", HardwareID: "hw-1", Evidence: evidenceForCode("hw-1", code)}
	if _, err := service.Enroll(context.Background(), code, request); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("expired code error = %v", err)
	}

	service, code = validService(t, now)
	request.OrganizationID = "org-2"
	request.Evidence = evidenceForCode("hw-1", code)
	if _, err := service.Enroll(context.Background(), code, request); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("wrong-org code error = %v", err)
	}
}

func TestEnrollRejectsNonceNotBoundToEnrollmentCode(t *testing.T) {
	service, code := validService(t, time.Unix(1000, 0))
	_, err := service.Enroll(context.Background(), code, Request{
		OrganizationID: "org-1",
		HardwareID:     "hw-1",
		Evidence:       Evidence{HardwareID: "hw-1", Nonce: []byte("endpoint-chosen")},
	})
	if !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("unbound nonce error = %v, want ErrAttestationInvalid", err)
	}
}

func TestEnrollRejectsMismatchedEvidenceIdentity(t *testing.T) {
	service, code := validService(t, time.Unix(1000, 0))
	_, err := service.Enroll(context.Background(), code, Request{
		OrganizationID: "org-1",
		HardwareID:     "hw-1",
		Evidence:       Evidence{HardwareID: "hw-attacker"},
	})
	if !errors.Is(err, ErrAttestationInvalid) {
		t.Fatalf("identity mismatch error = %v", err)
	}
}

func TestEnrollUsesAtomicFinalizerInsteadOfStandaloneConsume(t *testing.T) {
	now := time.Unix(1000, 0)
	store := &atomicCodeStore{MemoryCodeStore: NewMemoryCodeStore()}
	service := NewEnrollmentService(store,
		verifierFunc(func(context.Context, Evidence) error { return nil }),
		issuerFunc(func(context.Context, VerifiedIdentity) ([]byte, error) { return []byte("certificate"), nil }),
		func() time.Time { return now },
	)
	code, err := service.MintCode(context.Background(), "org-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Enroll(context.Background(), code, Request{
		OrganizationID: "org-1", HardwareID: "hw-1", Evidence: evidenceForCode("hw-1", code),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !store.finalizeCalled || store.consumeCalled {
		t.Fatalf("finalize=%v consume=%v", store.finalizeCalled, store.consumeCalled)
	}
}
