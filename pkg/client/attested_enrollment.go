package client

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	grpcapi "aftersec/pkg/api/grpc"
	"google.golang.org/grpc"
)

type EnrollmentRPC interface {
	Enroll(context.Context, *grpcapi.EnrollRequest, ...grpc.CallOption) (*grpcapi.EnrollResponse, error)
}

type CredentialStore interface {
	Save([]byte, string) error
}

// RunAttestedEnrollment performs the complete client enrollment transaction:
// collect evidence, call the server, verify credentials, then persist them.
func RunAttestedEnrollment(ctx context.Context, rpc EnrollmentRPC, provider EvidenceProvider, store CredentialStore, caPEM []byte, details EnrollmentDetails, now time.Time) (*grpcapi.EnrollResponse, error) {
	if rpc == nil || store == nil {
		return nil, fmt.Errorf("enrollment RPC and credential store are required")
	}
	request, err := BuildAttestedEnrollRequest(ctx, provider, details)
	if err != nil {
		return nil, err
	}
	response, err := rpc.Enroll(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("attested enrollment RPC: %w", err)
	}
	if response == nil || !response.Success || response.TenantId != details.OrganizationID ||
		response.AccessToken == "" || len(response.ClientCertificate) == 0 {
		return nil, fmt.Errorf("attested enrollment response is incomplete or mismatched")
	}
	if err := VerifyEnrollmentCertificate(response.ClientCertificate, caPEM, details.OrganizationID, details.HardwareID, provider.PublicKey(), now); err != nil {
		return nil, err
	}
	if err := store.Save(response.ClientCertificate, response.AccessToken); err != nil {
		return nil, fmt.Errorf("persist enrollment credentials: %w", err)
	}
	return response, nil
}

// VerifyEnrollmentCertificate verifies the returned certificate before any
// credential is persisted. Threats: wrong CA, identity/key substitution,
// expiry, and non-client-auth certificates are rejected.
func VerifyEnrollmentCertificate(certPEM, caPEM []byte, organizationID, hardwareID string, expectedKey crypto.PublicKey, now time.Time) error {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("decode enrollment certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse enrollment certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("parse enrollment CA")
	}
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("verify enrollment certificate: %w", err)
	}
	if certificate.Subject.CommonName != hardwareID || len(certificate.Subject.Organization) != 1 || certificate.Subject.Organization[0] != organizationID {
		return fmt.Errorf("enrollment certificate identity mismatch")
	}
	wantKey, err := x509.MarshalPKIXPublicKey(expectedKey)
	if err != nil {
		return fmt.Errorf("marshal expected endpoint key: %w", err)
	}
	gotKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate endpoint key: %w", err)
	}
	if !bytes.Equal(gotKey, wantKey) {
		return fmt.Errorf("enrollment certificate public key mismatch")
	}
	return nil
}

// FileCredentialStore is permitted only for explicit development mode.
// Production refresh tokens belong in Keychain/keyring providers.
type FileCredentialStore struct {
	directory string
	mode      string
}

func NewFileCredentialStore(directory, mode string) *FileCredentialStore {
	return &FileCredentialStore{directory: directory, mode: mode}
}

func (s *FileCredentialStore) CertificatePath() string {
	return filepath.Join(s.directory, "client.crt")
}

func (s *FileCredentialStore) RefreshTokenPath() string {
	return filepath.Join(s.directory, "refresh.token")
}

func (s *FileCredentialStore) Save(certificate []byte, refreshToken string) error {
	if s.mode != "development" {
		return fmt.Errorf("file credential storage is development-only")
	}
	if len(certificate) == 0 || refreshToken == "" {
		return fmt.Errorf("certificate and refresh token are required")
	}
	if err := os.MkdirAll(s.directory, 0700); err != nil {
		return fmt.Errorf("create credential directory: %w", err)
	}
	if err := os.Chmod(s.directory, 0700); err != nil {
		return fmt.Errorf("secure credential directory: %w", err)
	}
	if err := writePrivateFile(s.CertificatePath(), certificate); err != nil {
		return err
	}
	if err := writePrivateFile(s.RefreshTokenPath(), []byte(refreshToken)); err != nil {
		return err
	}
	return nil
}

func writePrivateFile(path string, data []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0600); err != nil {
		return fmt.Errorf("write private credential: %w", err)
	}
	if err := os.Chmod(temporary, 0600); err != nil {
		os.Remove(temporary)
		return fmt.Errorf("secure private credential: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		os.Remove(temporary)
		return fmt.Errorf("install private credential: %w", err)
	}
	return nil
}
