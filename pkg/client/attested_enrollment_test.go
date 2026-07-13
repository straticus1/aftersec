package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"os"
	"testing"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"aftersec/pkg/attestation"
	"google.golang.org/grpc"
)

type enrollmentRPCFunc func(context.Context, *grpcapi.EnrollRequest) (*grpcapi.EnrollResponse, error)

func (f enrollmentRPCFunc) Enroll(ctx context.Context, req *grpcapi.EnrollRequest, _ ...grpc.CallOption) (*grpcapi.EnrollResponse, error) {
	return f(ctx, req)
}

type captureCredentialStore struct {
	certificate []byte
	token       string
}

func (s *captureCredentialStore) Save(certificate []byte, token string) error {
	s.certificate = append([]byte(nil), certificate...)
	s.token = token
	return nil
}

func issuedEnrollmentCertificate(t *testing.T, now time.Time) ([]byte, []byte, ed25519.PublicKey) {
	t.Helper()
	issuer, caPEM, err := attestation.NewDevelopmentIssuer(func() time.Time { return now }, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := issuer.IssueClientCertificate(context.Background(), attestation.VerifiedIdentity{
		OrganizationID: "org-1", HardwareID: "hw-1", Hostname: "host-1", PublicKey: publicDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	return certificate, caPEM, publicKey
}

func TestVerifyEnrollmentCertificateAcceptsExpectedIdentityAndKey(t *testing.T) {
	now := time.Unix(1000, 0)
	certificate, caPEM, publicKey := issuedEnrollmentCertificate(t, now)
	if err := VerifyEnrollmentCertificate(certificate, caPEM, "org-1", "hw-1", publicKey, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyEnrollmentCertificateRejectsSubstitutedHardwareIdentity(t *testing.T) {
	now := time.Unix(1000, 0)
	certificate, caPEM, publicKey := issuedEnrollmentCertificate(t, now)
	if err := VerifyEnrollmentCertificate(certificate, caPEM, "org-1", "hw-attacker", publicKey, now.Add(time.Minute)); err == nil {
		t.Fatal("certificate for another hardware identity was accepted")
	}
}

func TestDevelopmentFileCredentialStoreRejectsProductionMode(t *testing.T) {
	store := NewFileCredentialStore(t.TempDir(), "production")
	if err := store.Save([]byte("certificate"), "refresh-token"); err == nil {
		t.Fatal("plaintext file credential store accepted production mode")
	}
}

func TestDevelopmentFileCredentialStoreUsesPrivatePermissions(t *testing.T) {
	store := NewFileCredentialStore(t.TempDir(), "development")
	if err := store.Save([]byte("certificate"), "refresh-token"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{store.CertificatePath(), store.RefreshTokenPath()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("%s permissions = %o, want 0600", path, info.Mode().Perm())
		}
	}
}

func TestRunAttestedEnrollmentVerifiesThenPersistsResponse(t *testing.T) {
	now := time.Now().UTC()
	issuer, caPEM, err := attestation.NewDevelopmentIssuer(func() time.Time { return now }, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, quotePrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewDevelopmentEvidenceProvider("development", "darwin", quotePrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	rpc := enrollmentRPCFunc(func(ctx context.Context, req *grpcapi.EnrollRequest) (*grpcapi.EnrollResponse, error) {
		certificate, err := issuer.IssueClientCertificate(ctx, attestation.VerifiedIdentity{
			OrganizationID: req.OrganizationId, HardwareID: req.HardwareId, Hostname: req.Hostname, PublicKey: req.PublicKey,
		})
		if err != nil {
			return nil, err
		}
		return &grpcapi.EnrollResponse{Success: true, TenantId: req.OrganizationId, AccessToken: "refresh", ClientCertificate: certificate}, nil
	})
	store := &captureCredentialStore{}
	response, err := RunAttestedEnrollment(context.Background(), rpc, provider, store, caPEM, EnrollmentDetails{
		OrganizationID: "org-1", EnrollmentCode: "code", HardwareID: "hw-1", Hostname: "host-1",
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if response.TenantId != "org-1" || store.token != "refresh" || len(store.certificate) == 0 {
		t.Fatalf("response/store not completed: %#v %#v", response, store)
	}
}

func TestRunAttestedEnrollmentDoesNotPersistFailedResponse(t *testing.T) {
	_, quotePrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	provider, err := NewDevelopmentEvidenceProvider("development", "darwin", quotePrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := &captureCredentialStore{}
	_, err = RunAttestedEnrollment(context.Background(), enrollmentRPCFunc(func(context.Context, *grpcapi.EnrollRequest) (*grpcapi.EnrollResponse, error) {
		return &grpcapi.EnrollResponse{Success: false}, nil
	}), provider, store, []byte("bad-ca"), EnrollmentDetails{OrganizationID: "org-1", EnrollmentCode: "code", HardwareID: "hw-1"}, time.Now())
	if err == nil || store.token != "" || len(store.certificate) != 0 {
		t.Fatal("failed enrollment response was persisted")
	}
}

func TestNewPlatformCredentialStoreUsesFilesOnlyInDevelopment(t *testing.T) {
	store, err := NewPlatformCredentialStore("development", t.TempDir(), "hw-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*FileCredentialStore); !ok {
		t.Fatalf("development store type = %T, want FileCredentialStore", store)
	}
	store, err = NewPlatformCredentialStore("production", t.TempDir(), "hw-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.(*FileCredentialStore); ok {
		t.Fatal("production selected plaintext file credential store")
	}
}
